using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Sbroenne.WindowsMcp.Tailscale;

namespace Sbroenne.WindowsMcp.Hosting;

/// <summary>
/// Runs the HTTP transport behind Tailscale Serve: loopback Kestrel, a supervised foreground serve child that
/// dies with this process, and tailnet identity enforcement on every request.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class TailscaleServerHost
{
    private const long MaxRequestBodyBytes = 4 * 1024 * 1024;
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(20);

    /// <summary>
    /// Runs preflight checks and prints the report without starting the server.
    /// </summary>
    /// <param name="options">Parsed server options in Tailscale mode.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>0 when every check passed, 1 otherwise.</returns>
    public static async Task<int> CheckAsync(ServerOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        var cli = TailscaleCli.Resolve(options.TailscaleExecutable, out var resolveError);
        var report = cli is null
            ? TailscalePreflight.ResolutionFailed(resolveError ?? "Tailscale executable could not be verified.")
            : await new TailscalePreflight(cli).RunAsync(options, cancellationToken);

        Console.WriteLine(report.Format());
        return report.Passed ? 0 : 1;
    }

    /// <summary>
    /// Runs the server in Tailscale mode until it is asked to stop.
    /// </summary>
    /// <param name="options">Parsed server options in Tailscale mode.</param>
    /// <param name="serverVersion">Semver reported in the MCP handshake.</param>
    /// <param name="cancellationToken">Cancellation token that stops the host.</param>
    /// <returns>Process exit code.</returns>
    public static async Task<int> RunAsync(ServerOptions options, string serverVersion, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        var cli = TailscaleCli.Resolve(options.TailscaleExecutable, out var resolveError);
        if (cli is null)
        {
            Console.Error.WriteLine(resolveError ?? "Tailscale executable could not be verified.");
            return 1;
        }

        // Fail fast with the same guidance --tailscale-check gives, rather than launching into a broken serve.
        var preflight = await new TailscalePreflight(cli).RunAsync(options, cancellationToken);
        if (!preflight.Passed)
        {
            Console.Error.WriteLine(preflight.Format());
            return 1;
        }

        IAuditSink auditSink = options.AuditFilePath is null ? new NullAuditSink() : new AuditFileSink(options.AuditFilePath);
        try
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                Args = [$"--{WebHostDefaults.PreventHostingStartupKey}=true"],
            });

            builder.Configuration.Sources.Clear();
            builder.WebHost.ConfigureKestrel(kestrel =>
            {
                kestrel.AddServerHeader = false;
                kestrel.Limits.MaxRequestBodySize = MaxRequestBodyBytes;

                // Serve terminates TLS and forwards to us on loopback, so we never bind anything else.
                kestrel.Listen(System.Net.IPAddress.Loopback, options.Port);
            });

            builder.Logging.ClearProviders();
            builder.Logging.AddConsole(consoleOptions => consoleOptions.LogToStandardErrorThreshold = LogLevel.Trace);
            builder.Logging.SetMinimumLevel(LogLevel.Information);
            builder.Logging.AddFilter("Microsoft", LogLevel.Warning);

            builder.Services.AddHttpContextAccessor();
            builder.Services.AddSingleton<ITailscaleCli>(cli);
            builder.Services.AddSingleton(options);
            builder.Services.AddSingleton(TimeProvider.System);

            // The audit filter is registered before the app is built, so it gets its own logger factory rather than
            // the app's. The factory is disposed with the try scope, after the app has stopped and no request can log.
            using var auditLoggerFactory = LoggerFactory.Create(logging =>
            {
                logging.AddConsole(consoleOptions => consoleOptions.LogToStandardErrorThreshold = LogLevel.Trace);
                logging.SetMinimumLevel(LogLevel.Information);
            });
            var auditFilter = ToolCallAudit.CreateFilter(auditLoggerFactory.CreateLogger("Sbroenne.WindowsMcp.Audit"), auditSink);

            builder.Services
                .AddWindowsMcpServer(serverVersion)
                .WithHttpTransport(transport => transport.Stateless = true)
                .WithRequestFilters(filters => filters.AddCallToolFilter(auditFilter));

            await using var app = builder.Build();

            // Identity is the gate: loopback source, a single Serve-injected login header, whois cross-check, and
            // the allow list. It runs before the endpoint so an unauthenticated request never reaches a tool.
            app.UseWhen(
                context => context.Request.Path.StartsWithSegments(options.Path),
                branch => branch.UseTailscaleIdentity());
            app.MapGet("/healthz", () => Results.Json(new { status = "ok", version = serverVersion, transport = "http" }));
            app.MapMcp(options.Path);

            await app.StartAsync(cancellationToken);

            var loopbackPort = ResolveBoundPort(app);
            await using var supervisor = new ServeSupervisor(
                cli,
                new ProcessLauncher(),
                options,
                loopbackPort,
                TimeProvider.System,
                app.Services.GetRequiredService<ILogger<ServeSupervisor>>());

            using var startupCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            startupCts.CancelAfter(StartupTimeout);
            try
            {
                await supervisor.StartAsync(startupCts.Token);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                Console.Error.WriteLine($"Could not start Tailscale Serve: {ex.Message}");
                await app.StopAsync(CancellationToken.None);
                return 1;
            }

            PrintBanner(cli, options, loopbackPort, cancellationToken);

            await app.WaitForShutdownAsync(cancellationToken);
            await supervisor.StopAsync(CancellationToken.None);
            return 0;
        }
        finally
        {
            (auditSink as IDisposable)?.Dispose();
        }
    }

    private static int ResolveBoundPort(WebApplication app)
    {
        var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses
            ?? throw new InvalidOperationException("Kestrel reported no bound address.");
        foreach (var address in addresses)
        {
            if (Uri.TryCreate(address, UriKind.Absolute, out var uri))
            {
                return uri.Port;
            }
        }

        throw new InvalidOperationException("Kestrel reported no parseable bound address.");
    }

    private static void PrintBanner(TailscaleCli cli, ServerOptions options, int loopbackPort, CancellationToken cancellationToken)
    {
        var status = cli.GetStatusAsync(cancellationToken).GetAwaiter().GetResult();
        var dnsName = status?.DnsName;
        var portSuffix = options.ServePort == 443 ? string.Empty : ":" + options.ServePort.ToString(CultureInfo.InvariantCulture);
        var url = dnsName is null
            ? $"https://<this-node>.<tailnet>.ts.net{portSuffix}{options.Path}"
            : $"https://{dnsName}{portSuffix}{options.Path}";

        Console.WriteLine($"Windows MCP is available on your tailnet:");
        Console.WriteLine($"  {url}");
        Console.WriteLine("Add it on another machine:");
        Console.WriteLine($"  claude mcp add --transport http windows {url}");
        Console.WriteLine($"Allowed logins: {string.Join(", ", options.AllowedLogins)}");
        Console.WriteLine($"(serving loopback port {loopbackPort.ToString(CultureInfo.InvariantCulture)})");
    }
}

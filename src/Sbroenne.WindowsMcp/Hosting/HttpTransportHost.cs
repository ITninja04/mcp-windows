using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sbroenne.WindowsMcp.Hosting;

/// <summary>
/// Hosts the MCP server over Streamable HTTP with Kestrel. Binds only what the operator asked for
/// (loopback by default) and ignores configuration files and environment variables that could add listeners.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class HttpTransportHost
{
    private const long MaxRequestBodyBytes = 4 * 1024 * 1024;

    /// <summary>
    /// Runs the HTTP transport until the host is asked to stop.
    /// </summary>
    /// <param name="options">Parsed server options with <see cref="ServerOptions.Transport"/> set to HTTP.</param>
    /// <param name="serverVersion">Semver reported in the MCP handshake.</param>
    /// <param name="cancellationToken">Cancellation token that stops the host.</param>
    /// <returns>Process exit code.</returns>
    public static async Task<int> RunAsync(ServerOptions options, string serverVersion, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        var startedAt = Stopwatch.GetTimestamp();

        // Process arguments were parsed by ServerOptions already; the only argument the builder sees turns off
        // hosting-startup assembly injection, which is decided at builder creation.
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = [$"--{WebHostDefaults.PreventHostingStartupKey}=true"],
        });

        // Drop appsettings.json, environment variables, and command-line configuration so nothing outside this
        // process can add a Kestrel endpoint (Kestrel:Endpoints, ASPNETCORE_URLS).
        builder.Configuration.Sources.Clear();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = MaxRequestBodyBytes;
            foreach (var address in options.ListenAddresses)
            {
                kestrel.Listen(address, options.Port);
            }
        });

        // stdout is not the protocol channel here, so Information and up goes to stderr (audit lines included).
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole(consoleOptions =>
        {
            consoleOptions.LogToStandardErrorThreshold = LogLevel.Trace;
        });
        builder.Logging.SetMinimumLevel(LogLevel.Information);
        builder.Logging.AddFilter("Microsoft", LogLevel.Warning);

        builder.Services.AddHttpContextAccessor();
        builder.Services
            .AddWindowsMcpServer(serverVersion)
            .WithHttpTransport(transport =>
            {
                // No tool uses sampling or elicitation, and one desktop sits behind this process, so sessions add nothing.
                transport.Stateless = true;
            });

        await using var app = builder.Build();

        var allowedHosts = BuildAllowedHosts(options);
        app.Use((context, next) => RejectUnexpectedHostOrOriginAsync(context, next, allowedHosts));
        app.MapGet("/healthz", () => Results.Json(new
        {
            status = "ok",
            version = serverVersion,
            transport = "http",
            path = options.Path,
            uptimeSeconds = (long)Stopwatch.GetElapsedTime(startedAt).TotalSeconds,
        }));
        app.MapMcp(options.Path);

        await app.StartAsync(cancellationToken);

        foreach (var url in ResolveBoundUrls(app, options.Path))
        {
            Console.WriteLine($"sbroenne.windows-mcp {serverVersion} listening on {url} (transport: http)");
        }

        if (!options.BindsLoopbackOnly)
        {
            Console.Error.WriteLine(
                $"WARNING: bound to {options.Host}. Every machine that can reach this port can control this desktop. " +
                "Put a tailnet, VPN, or authenticated reverse proxy in front of it, or bind loopback and tunnel.");
        }

        await app.WaitForShutdownAsync(cancellationToken);
        return 0;
    }

    /// <summary>
    /// Host names a request may carry. A browser page on another site can reach 127.0.0.1 through DNS
    /// rebinding, but its Host header names that other site, so anything not on this list is refused.
    /// </summary>
    private static HashSet<string> BuildAllowedHosts(ServerOptions options)
    {
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { options.Host };
        foreach (var address in options.ListenAddresses)
        {
            hosts.Add(address.ToString());
            if (IPAddress.IsLoopback(address))
            {
                hosts.Add("localhost");
            }
        }

        return hosts;
    }

    private static Task RejectUnexpectedHostOrOriginAsync(HttpContext context, RequestDelegate next, HashSet<string> allowedHosts)
    {
        var host = context.Request.Host.Host;
        if (string.IsNullOrEmpty(host) || !allowedHosts.Contains(host))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

        // MCP clients do not send Origin; browsers do, and no browser page should be able to drive this desktop.
        if (context.Request.Headers.TryGetValue("Origin", out var origin) &&
            (!Uri.TryCreate(origin.ToString(), UriKind.Absolute, out var originUri) || !allowedHosts.Contains(originUri.Host)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

        return next(context);
    }

    private static List<string> ResolveBoundUrls(WebApplication app, string path)
    {
        // Ask the server for its addresses so --port 0 reports the port the OS picked.
        var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses;
        var urls = new List<string>();
        foreach (var address in addresses ?? [])
        {
            urls.Add(address.TrimEnd('/') + path);
        }

        return urls;
    }
}

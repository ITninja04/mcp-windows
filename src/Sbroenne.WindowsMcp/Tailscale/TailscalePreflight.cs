using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Sbroenne.WindowsMcp.Hosting;
using Sbroenne.WindowsMcp.Native;

namespace Sbroenne.WindowsMcp.Tailscale;

/// <summary>
/// The outcome of one startup check.
/// </summary>
/// <param name="Name">Short name of the check, stable enough to be matched on.</param>
/// <param name="Passed">True when the check found nothing wrong.</param>
/// <param name="Detail">One line saying what was found, or null when there is nothing to add.</param>
/// <param name="FixHint">One actionable line telling the operator what to do, or null when the check passed.</param>
public sealed record PreflightCheck(string Name, bool Passed, string? Detail, string? FixHint);

/// <summary>
/// The result of every startup check, in the order they ran.
/// </summary>
/// <param name="Passed">True only when every check passed.</param>
/// <param name="Checks">Each check, in the order it ran.</param>
public sealed record PreflightReport(bool Passed, IReadOnlyList<PreflightCheck> Checks)
{
    /// <summary>
    /// Renders the report as plain text for the console.
    /// </summary>
    /// <returns>One line per check, with the fix hint indented under any failure.</returns>
    public string Format()
    {
        var builder = new StringBuilder();
        foreach (var check in Checks)
        {
            builder.Append(check.Passed ? "PASS  " : "FAIL  ").Append(check.Name);
            if (!string.IsNullOrEmpty(check.Detail))
            {
                builder.Append(": ").Append(check.Detail);
            }

            builder.AppendLine();

            if (!check.Passed && !string.IsNullOrEmpty(check.FixHint))
            {
                builder.Append("      fix: ").AppendLine(check.FixHint);
            }
        }

        builder.Append(Passed ? "All Tailscale preflight checks passed." : "Tailscale preflight failed.").AppendLine();
        return builder.ToString();
    }

    /// <summary>
    /// Renders the report as JSON, for callers that want to act on it rather than read it.
    /// </summary>
    /// <returns>An indented JSON document with a passed flag and the list of checks.</returns>
    public string ToJson()
    {
        var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("passed", Passed);
            writer.WriteStartArray("checks");
            foreach (var check in Checks)
            {
                writer.WriteStartObject();
                writer.WriteString("name", check.Name);
                writer.WriteBoolean("passed", check.Passed);
                writer.WriteString("detail", check.Detail);
                writer.WriteString("fixHint", check.FixHint);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }
}

/// <summary>
/// Runs the checks that have to pass before the server will accept tailnet traffic.
/// </summary>
/// <remarks>
/// Every one of these is a condition that would otherwise fail later, at a point where the failure is
/// confusing or, worse, silently insecure. Running them up front turns each into one line the operator can
/// act on. Checks run in order and none of them changes any state.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class TailscalePreflight
{
    /// <summary>The oldest Tailscale release the server is willing to drive.</summary>
    public static readonly Version MinimumTailscaleVersion = new(1, 60, 0);

    /// <summary>Name of the check that confirms tailscale.exe was resolved and is signed by Tailscale.</summary>
    internal const string ExecutableCheck = "tailscale.exe";

    /// <summary>Name of the check that confirms the CLI is new enough.</summary>
    internal const string VersionCheck = "Tailscale version";

    /// <summary>Name of the check that confirms the local backend is running.</summary>
    internal const string BackendCheck = "Tailscale backend";

    /// <summary>Name of the check that confirms the tailnet issues HTTPS certificates for this node.</summary>
    internal const string HttpsCheck = "Tailnet HTTPS";

    /// <summary>Name of the check that confirms this process shares the interactive desktop session.</summary>
    internal const string SessionCheck = "Interactive session";

    /// <summary>Name of the check that confirms the tailnet serve port is free.</summary>
    internal const string ServePortCheck = "Serve port";

    /// <summary>Name of the check that confirms no Funnel route exists.</summary>
    internal const string FunnelCheck = "Funnel";

    /// <summary>Name of the check that confirms the loopback port Kestrel wants is free.</summary>
    internal const string LoopbackPortCheck = "Loopback port";

    private readonly ITailscaleCli _cli;
    private readonly Func<bool> _interactiveSessionProbe;
    private readonly Func<int, string?> _loopbackPortProbe;

    /// <summary>
    /// Initializes a new instance of the <see cref="TailscalePreflight"/> class.
    /// </summary>
    /// <param name="cli">A resolved and verified Tailscale CLI.</param>
    public TailscalePreflight(ITailscaleCli cli)
        : this(cli, SessionNativeMethods.IsInteractiveConsoleSession, ProbeLoopbackPort)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TailscalePreflight"/> class with the environment probes
    /// replaced, so tests can drive the session and port checks without touching the machine.
    /// </summary>
    /// <param name="cli">A resolved and verified Tailscale CLI.</param>
    /// <param name="interactiveSessionProbe">Returns true when this process shares the console session.</param>
    /// <param name="loopbackPortProbe">Returns null when the loopback port is free, otherwise the reason it is not.</param>
    internal TailscalePreflight(ITailscaleCli cli, Func<bool> interactiveSessionProbe, Func<int, string?> loopbackPortProbe)
    {
        ArgumentNullException.ThrowIfNull(cli);
        ArgumentNullException.ThrowIfNull(interactiveSessionProbe);
        ArgumentNullException.ThrowIfNull(loopbackPortProbe);

        _cli = cli;
        _interactiveSessionProbe = interactiveSessionProbe;
        _loopbackPortProbe = loopbackPortProbe;
    }

    /// <summary>
    /// Builds the report for the case where tailscale.exe could not be resolved at all, so there is no CLI
    /// to construct a <see cref="TailscalePreflight"/> with.
    /// </summary>
    /// <param name="error">The reason <see cref="TailscaleCli.Resolve"/> gave.</param>
    /// <returns>A failed report holding the single check that could be run.</returns>
    public static PreflightReport ResolutionFailed(string error)
    {
        ArgumentNullException.ThrowIfNull(error);

        var check = new PreflightCheck(
            ExecutableCheck,
            false,
            error,
            "Install Tailscale from https://tailscale.com/download, or pass --tailscale-exe with the full path to a signed tailscale.exe.");
        return new PreflightReport(false, [check]);
    }

    /// <summary>
    /// Runs every startup check in order.
    /// </summary>
    /// <param name="options">The parsed server options the checks are measured against.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The report. It never throws for a failed check; a failure is a check result.</returns>
    public async Task<PreflightReport> RunAsync(ServerOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var checks = new List<PreflightCheck>
        {
            // Reaching this method at all means Resolve accepted the executable, so this check records what it found.
            new(ExecutableCheck, true, $"verified Authenticode signature at {_cli.ExecutablePath}", null),
            await CheckVersionAsync(cancellationToken),
        };

        var status = await _cli.GetStatusAsync(cancellationToken);
        checks.Add(CheckBackend(status));
        checks.Add(CheckHttps(status));
        checks.Add(CheckSession());

        var serveStatus = await _cli.GetServeStatusAsync(cancellationToken);
        checks.Add(CheckServePort(serveStatus, options));
        checks.Add(CheckFunnel(serveStatus));
        checks.Add(CheckLoopbackPort(options));

        return new PreflightReport(checks.TrueForAll(check => check.Passed), checks);
    }

    private async Task<PreflightCheck> CheckVersionAsync(CancellationToken cancellationToken)
    {
        var version = await _cli.GetVersionAsync(cancellationToken);
        const string fix = "Update Tailscale to 1.60.0 or newer from https://tailscale.com/download.";

        if (version is null)
        {
            return new PreflightCheck(VersionCheck, false, "the client version could not be read from 'tailscale version'", fix);
        }

        return version >= MinimumTailscaleVersion
            ? new PreflightCheck(VersionCheck, true, version.ToString(), null)
            : new PreflightCheck(
                VersionCheck,
                false,
                $"found {version}, need {MinimumTailscaleVersion} or newer",
                fix);
    }

    private static PreflightCheck CheckBackend(TailscaleStatus? status)
    {
        const string fix = "Run 'tailscale up' and sign in, then start the server again.";

        if (status is null)
        {
            return new PreflightCheck(BackendCheck, false, "'tailscale status --json' could not be read; the service may not be running", fix);
        }

        return status.IsRunning
            ? new PreflightCheck(BackendCheck, true, $"running as {status.DnsName ?? "this node"}", null)
            : new PreflightCheck(BackendCheck, false, $"backend state is {status.BackendState}, not Running", fix);
    }

    private static PreflightCheck CheckHttps(TailscaleStatus? status)
    {
        const string fix = "Enable MagicDNS and HTTPS certificates for this tailnet in the Tailscale admin console under DNS.";

        if (status is null)
        {
            return new PreflightCheck(HttpsCheck, false, "'tailscale status --json' could not be read, so HTTPS could not be confirmed", fix);
        }

        return status.HttpsEnabled
            ? new PreflightCheck(HttpsCheck, true, $"certificate available for {string.Join(", ", status.CertDomains)}", null)
            : new PreflightCheck(HttpsCheck, false, "this tailnet does not issue HTTPS certificates for this node, so Serve cannot terminate TLS", fix);
    }

    private PreflightCheck CheckSession()
    {
        // Serve would happily start without a desktop, and every tool call would then fail at the point of use.
        return _interactiveSessionProbe()
            ? new PreflightCheck(SessionCheck, true, "running in the interactive console session", null)
            : new PreflightCheck(
                SessionCheck,
                false,
                "this process has no interactive desktop, so no tool could move the mouse or read the screen",
                "Start the server in the console session as the signed-in user, not as a Windows service or over an SSH session.");
    }

    private static PreflightCheck CheckServePort(TailscaleServeStatus? serveStatus, ServerOptions options)
    {
        var fix = $"Run 'tailscale serve --https={options.ServePort} off' to free the port, or start the server with --serve-port and a free port.";

        if (serveStatus is null)
        {
            return new PreflightCheck(ServePortCheck, false, "'tailscale serve status --json' could not be read", fix);
        }

        var conflict = serveStatus.Listeners.FirstOrDefault(
            listener => listener.Port == options.ServePort && !IsOurListener(listener, options));

        return conflict is null
            ? new PreflightCheck(ServePortCheck, true, $"tailnet port {options.ServePort} is free", null)
            : new PreflightCheck(
                ServePortCheck,
                false,
                $"tailnet port {options.ServePort} already serves {conflict.HostPort}{conflict.Path} to {conflict.ProxyTarget}",
                fix);
    }

    private static PreflightCheck CheckFunnel(TailscaleServeStatus? serveStatus)
    {
        const string fix = "Run 'tailscale funnel off' to remove the public route; this server must never be reachable from the internet.";

        if (serveStatus is null)
        {
            return new PreflightCheck(FunnelCheck, false, "'tailscale serve status --json' could not be read, so Funnel could not be ruled out", fix);
        }

        if (!serveStatus.AnyFunnel)
        {
            return new PreflightCheck(FunnelCheck, true, "no Funnel route is configured", null);
        }

        var exposed = serveStatus.Listeners.Where(listener => listener.AllowFunnel).Select(listener => listener.HostPort).Distinct(StringComparer.OrdinalIgnoreCase);
        return new PreflightCheck(
            FunnelCheck,
            false,
            $"Funnel exposes {string.Join(", ", exposed)} to the public internet",
            fix);
    }

    private PreflightCheck CheckLoopbackPort(ServerOptions options)
    {
        if (options.Port == 0)
        {
            return new PreflightCheck(LoopbackPortCheck, true, "port 0 asks the operating system for a free port", null);
        }

        var failure = _loopbackPortProbe(options.Port);
        return failure is null
            ? new PreflightCheck(LoopbackPortCheck, true, $"127.0.0.1:{options.Port.ToString(CultureInfo.InvariantCulture)} is free", null)
            : new PreflightCheck(
                LoopbackPortCheck,
                false,
                $"127.0.0.1:{options.Port.ToString(CultureInfo.InvariantCulture)} cannot be bound: {failure}",
                $"Stop whatever is listening on 127.0.0.1:{options.Port.ToString(CultureInfo.InvariantCulture)}, or start the server with --port and a free port.");
    }

    private static bool IsOurListener(TailscaleServeListener listener, ServerOptions options)
    {
        // A leftover route from an earlier run of this server points back at our own loopback endpoint.
        // With --port 0 there is no fixed port to compare, so nothing can be claimed as ours.
        return options.Port != 0
            && Uri.TryCreate(listener.ProxyTarget, UriKind.Absolute, out var target)
            && IPAddress.TryParse(target.Host, out var host)
            && IPAddress.IsLoopback(host)
            && target.Port == options.Port;
    }

    private static string? ProbeLoopbackPort(int port)
    {
        var listener = new TcpListener(IPAddress.Loopback, port);
        try
        {
            listener.Start();
            return null;
        }
        catch (SocketException exception)
        {
            return exception.Message;
        }
        finally
        {
            listener.Dispose();
        }
    }
}

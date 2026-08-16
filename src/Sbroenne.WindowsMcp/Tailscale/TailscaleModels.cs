using System.Net;

namespace Sbroenne.WindowsMcp.Tailscale;

/// <summary>
/// Result of running the Tailscale CLI once: its exit code and captured output.
/// </summary>
/// <param name="ExitCode">Process exit code, or -1 when the process could not be started or timed out.</param>
/// <param name="StandardOutput">Captured standard output.</param>
/// <param name="StandardError">Captured standard error.</param>
public sealed record TailscaleCommandResult(int ExitCode, string StandardOutput, string StandardError)
{
    /// <summary>True when the command exited with code 0.</summary>
    public bool Succeeded => ExitCode == 0;
}

/// <summary>
/// The subset of <c>tailscale status --json</c> the server needs to decide whether Serve can run.
/// </summary>
/// <param name="BackendState">Backend state, e.g. "Running", "Stopped", "NeedsLogin".</param>
/// <param name="DnsName">This node's MagicDNS name without the trailing dot, or null when unknown.</param>
/// <param name="TailscaleIps">This node's tailnet IP addresses.</param>
/// <param name="MagicDnsSuffix">The tailnet's MagicDNS suffix, or null when unknown.</param>
/// <param name="CertDomains">Domains this node can obtain HTTPS certificates for; empty when HTTPS is disabled.</param>
/// <param name="HttpsEnabled">True when the tailnet allows HTTPS for this node (CertDomains non-empty and the https capability present).</param>
public sealed record TailscaleStatus(
    string BackendState,
    string? DnsName,
    IReadOnlyList<string> TailscaleIps,
    string? MagicDnsSuffix,
    IReadOnlyList<string> CertDomains,
    bool HttpsEnabled)
{
    /// <summary>True when the backend is running and ready to serve.</summary>
    public bool IsRunning => string.Equals(BackendState, "Running", StringComparison.Ordinal);
}

/// <summary>
/// One host and path served by <c>tailscale serve</c>, parsed from <c>serve status --json</c>.
/// </summary>
/// <param name="Port">The TCP port the listener is bound to.</param>
/// <param name="HostPort">The "host:port" the handler is registered under.</param>
/// <param name="Path">The URL path prefix, e.g. "/mcp".</param>
/// <param name="ProxyTarget">The local proxy target, e.g. "http://127.0.0.1:8765/mcp".</param>
/// <param name="Foreground">True when this listener belongs to a foreground serve session rather than a background config.</param>
/// <param name="AllowFunnel">True when this listener is exposed to the public internet via Funnel.</param>
public sealed record TailscaleServeListener(
    int Port,
    string HostPort,
    string Path,
    string ProxyTarget,
    bool Foreground,
    bool AllowFunnel);

/// <summary>
/// The parsed contents of <c>tailscale serve status --json</c>.
/// </summary>
/// <param name="Listeners">Every configured listener, foreground and background.</param>
public sealed record TailscaleServeStatus(IReadOnlyList<TailscaleServeListener> Listeners)
{
    /// <summary>True when any listener is exposed to the public internet via Funnel.</summary>
    public bool AnyFunnel => Listeners.Any(listener => listener.AllowFunnel);
}

/// <summary>
/// The identity behind a tailnet address, parsed from <c>tailscale whois --json</c>.
/// </summary>
/// <param name="LoginName">The user's login, e.g. "user@github". Empty for a tagged node.</param>
/// <param name="DisplayName">The user's display name, or null when unknown.</param>
/// <param name="NodeName">The peer node's MagicDNS name.</param>
/// <param name="Tags">ACL tags on the peer node; non-empty for a tagged (non-user) node.</param>
public sealed record TailscaleWhois(
    string LoginName,
    string? DisplayName,
    string NodeName,
    IReadOnlyList<string> Tags);

/// <summary>
/// Runs the Tailscale CLI and parses the JSON the server relies on. Implementations resolve the executable
/// from a trusted location and never from PATH, so a hijacked <c>tailscale.exe</c> cannot stand in for it.
/// </summary>
public interface ITailscaleCli
{
    /// <summary>The full, verified path to the Tailscale executable this instance runs.</summary>
    string ExecutablePath { get; }

    /// <summary>
    /// Runs the Tailscale CLI with the given arguments.
    /// </summary>
    /// <param name="arguments">Arguments passed as an argument vector, never a joined string.</param>
    /// <param name="timeout">How long to wait before killing the process and returning a failure.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The command's exit code and captured output.</returns>
    Task<TailscaleCommandResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken);

    /// <summary>Runs <c>status --json</c> and parses it, or returns null when the command fails or cannot be parsed.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed status, or null.</returns>
    Task<TailscaleStatus?> GetStatusAsync(CancellationToken cancellationToken);

    /// <summary>Runs <c>serve status --json</c> and parses it, or returns null when the command fails or cannot be parsed.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed serve status, or null.</returns>
    Task<TailscaleServeStatus?> GetServeStatusAsync(CancellationToken cancellationToken);

    /// <summary>Runs <c>whois --json</c> for an address and parses it, or returns null when the command fails or cannot be parsed.</summary>
    /// <param name="address">The tailnet address to look up.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed identity, or null.</returns>
    Task<TailscaleWhois?> WhoisAsync(IPAddress address, CancellationToken cancellationToken);

    /// <summary>Runs <c>version</c> and returns the parsed client version, or null when it cannot be determined.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The client version, or null.</returns>
    Task<Version?> GetVersionAsync(CancellationToken cancellationToken);
}

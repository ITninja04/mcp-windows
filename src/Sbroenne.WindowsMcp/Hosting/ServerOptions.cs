using System.Globalization;
using System.Net;

namespace Sbroenne.WindowsMcp.Hosting;

/// <summary>
/// Command-line options for the server process. Parsed once at startup by <see cref="TryParse"/>.
/// </summary>
/// <remarks>
/// The server has run for a long time with no arguments at all, so the defaults here reproduce that
/// behavior exactly: stdio transport, nothing listening. Every network-facing option must be asked for.
/// </remarks>
public sealed record ServerOptions
{
    /// <summary>Default loopback host for the HTTP transport.</summary>
    public const string DefaultHttpHost = "127.0.0.1";

    /// <summary>Default port for the HTTP transport.</summary>
    public const int DefaultHttpPort = 8765;

    /// <summary>Default route the MCP endpoint is mapped at.</summary>
    public const string DefaultHttpPath = "/mcp";

    /// <summary>Default tailnet-facing HTTPS port for Tailscale Serve.</summary>
    public const int DefaultServePort = 443;

    /// <summary>Which transport to run.</summary>
    public ServerTransport Transport { get; init; } = ServerTransport.Stdio;

    /// <summary>
    /// Address to bind when <see cref="Transport"/> is <see cref="ServerTransport.Http"/>. Must be an IP literal
    /// or "localhost"; host names are rejected so the bind address is never decided by DNS.
    /// </summary>
    public string Host { get; init; } = DefaultHttpHost;

    /// <summary>TCP port for the HTTP transport. Zero asks the OS for a free port, which is printed at startup.</summary>
    public int Port { get; init; } = DefaultHttpPort;

    /// <summary>Route prefix for the MCP endpoint, e.g. "/mcp".</summary>
    public string Path { get; init; } = DefaultHttpPath;

    /// <summary>True when the caller asked for usage text.</summary>
    public bool ShowHelp { get; init; }

    /// <summary>True when the caller asked for the version and service self-check.</summary>
    public bool ShowVersion { get; init; }

    /// <summary>
    /// True when the server runs behind Tailscale Serve: it binds loopback, starts and supervises a foreground
    /// <c>tailscale serve</c> child, and enforces tailnet identity on every request.
    /// </summary>
    public bool Tailscale { get; init; }

    /// <summary>The tailnet-facing HTTPS port Serve listens on (default 443).</summary>
    public int ServePort { get; init; } = DefaultServePort;

    /// <summary>Tailnet logins allowed to reach the server. Required in Tailscale mode; empty otherwise.</summary>
    public IReadOnlyList<string> AllowedLogins { get; init; } = [];

    /// <summary>
    /// When true (the default), a request's identity header is cross-checked against <c>tailscale whois</c> of the
    /// forwarded address. Turning it off reduces authentication to a header the peer sends and is strongly discouraged.
    /// </summary>
    public bool VerifyIdentity { get; init; } = true;

    /// <summary>Optional path to append a JSON-lines audit record per tool call, in addition to the log.</summary>
    public string? AuditFilePath { get; init; }

    /// <summary>Optional override for the Tailscale executable path. Resolved from a trusted location, never from PATH.</summary>
    public string? TailscaleExecutable { get; init; }

    /// <summary>True when the caller asked to run preflight checks and exit without serving.</summary>
    public bool CheckOnly { get; init; }

    /// <summary>
    /// True when the configured host only accepts connections from this machine.
    /// </summary>
    public bool BindsLoopbackOnly =>
        string.Equals(Host, "localhost", StringComparison.OrdinalIgnoreCase)
        || (IPAddress.TryParse(Host, out var address) && IPAddress.IsLoopback(address));

    /// <summary>
    /// The IP addresses Kestrel should listen on for the configured <see cref="Host"/>.
    /// "localhost" expands to both loopback families; anything else is the single parsed literal.
    /// </summary>
    public IReadOnlyList<IPAddress> ListenAddresses =>
        string.Equals(Host, "localhost", StringComparison.OrdinalIgnoreCase)
            ? [IPAddress.Loopback, IPAddress.IPv6Loopback]
            : [IPAddress.Parse(Host)];

    /// <summary>Usage text printed for --help and on a usage error.</summary>
    public static string Usage =>
        """
        Usage: Sbroenne.WindowsMcp.exe [options]

        Runs the Windows automation MCP server. With no options the server speaks MCP over
        stdin/stdout, which is what VS Code, Claude Code, and the plugin expect.

        Options:
          --transport <stdio|http>   Transport to use (default: stdio).
          --host <address>           HTTP bind address: an IP literal or "localhost" (default: 127.0.0.1).
                                     Anything other than loopback lets every machine that can reach the
                                     port control this desktop. Prefer a tailnet or a tunnel over --host.
          --port <number>            HTTP port, 0 = pick a free port (default: 8765).
          --path <route>             HTTP route for the MCP endpoint (default: /mcp).
          --tailscale                Serve behind Tailscale Serve, tailnet-only, with identity checks.
          --allow <login>            Tailnet login allowed to connect (repeatable; required with --tailscale).
          --serve-port <number>      Tailnet-facing HTTPS port for Serve (default: 443).
          --no-verify-identity       Skip the whois cross-check (reduces auth to a header; discouraged).
          --audit-file <path>        Append a JSON-lines audit record per tool call.
          --tailscale-exe <path>     Path to tailscale.exe (default: the Program Files install).
          --tailscale-check          Run Tailscale preflight checks and exit.
          --version, -v              Print the version and check service initialization.
          --help, -h                 Show this text.

        Examples:
          Sbroenne.WindowsMcp.exe
          Sbroenne.WindowsMcp.exe --transport http
          Sbroenne.WindowsMcp.exe --transport http --port 9000 --path /windows
        """;

    /// <summary>
    /// Parses the process arguments. Returns false with a one-line <paramref name="error"/> when the
    /// arguments are not valid; the caller prints it together with <see cref="Usage"/> and exits.
    /// </summary>
    /// <param name="args">Raw process arguments.</param>
    /// <param name="options">The parsed options on success, or the defaults on failure.</param>
    /// <param name="error">Human-readable reason the arguments were rejected, or null on success.</param>
    /// <returns>True when <paramref name="options"/> can be used.</returns>
    public static bool TryParse(string[] args, out ServerOptions options, out string? error)
    {
        ArgumentNullException.ThrowIfNull(args);

        options = new ServerOptions();
        error = null;

        var transport = ServerTransport.Stdio;
        var host = DefaultHttpHost;
        var port = DefaultHttpPort;
        var path = DefaultHttpPath;
        var showHelp = false;
        var httpOptionSeen = false;
        var hostSpecified = false;
        var tailscale = false;
        var servePort = DefaultServePort;
        var verifyIdentity = true;
        var checkOnly = false;
        string? auditFilePath = null;
        string? tailscaleExecutable = null;
        var allowedLogins = new List<string>();

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            var (name, inlineValue) = SplitInlineValue(arg);

            // Funnel exposes a service to the public internet. This server controls the desktop and must never
            // be reachable that way, so any mention of funnel anywhere on the command line is refused outright.
            if (arg.Contains("funnel", StringComparison.OrdinalIgnoreCase))
            {
                error = "funnel is not supported: this server must never be exposed to the public internet.";
                return false;
            }

            switch (name.ToLowerInvariant())
            {
                case "--help":
                case "-h":
                    showHelp = true;
                    break;

                case "--version":
                case "-v":
                    options = new ServerOptions { ShowVersion = true };
                    return true;

                case "--transport":
                    if (!TryTakeValue(args, ref i, inlineValue, name, out var transportValue, out error))
                    {
                        return false;
                    }

                    if (!TryParseTransport(transportValue, out transport))
                    {
                        error = $"Unknown transport '{transportValue}'. Use stdio or http.";
                        return false;
                    }

                    break;

                case "--host":
                    if (!TryTakeValue(args, ref i, inlineValue, name, out host, out error))
                    {
                        return false;
                    }

                    httpOptionSeen = true;
                    hostSpecified = true;
                    break;

                case "--port":
                    if (!TryTakeValue(args, ref i, inlineValue, name, out var portValue, out error))
                    {
                        return false;
                    }

                    if (!int.TryParse(portValue, NumberStyles.None, CultureInfo.InvariantCulture, out port) || port > ushort.MaxValue)
                    {
                        error = $"Invalid port '{portValue}'. Use a number from 0 to 65535.";
                        return false;
                    }

                    httpOptionSeen = true;
                    break;

                case "--path":
                    if (!TryTakeValue(args, ref i, inlineValue, name, out path, out error))
                    {
                        return false;
                    }

                    httpOptionSeen = true;
                    break;

                case "--tailscale":
                    tailscale = true;
                    break;

                case "--serve-port":
                    if (!TryTakeValue(args, ref i, inlineValue, name, out var servePortValue, out error))
                    {
                        return false;
                    }

                    if (!int.TryParse(servePortValue, NumberStyles.None, CultureInfo.InvariantCulture, out servePort) || servePort is < 1 or > ushort.MaxValue)
                    {
                        error = $"Invalid serve port '{servePortValue}'. Use a number from 1 to 65535.";
                        return false;
                    }

                    break;

                case "--allow":
                    if (!TryTakeValue(args, ref i, inlineValue, name, out var login, out error))
                    {
                        return false;
                    }

                    allowedLogins.Add(login);
                    break;

                case "--verify-identity":
                    verifyIdentity = true;
                    break;

                case "--no-verify-identity":
                    verifyIdentity = false;
                    break;

                case "--audit-file":
                    if (!TryTakeValue(args, ref i, inlineValue, name, out auditFilePath, out error))
                    {
                        return false;
                    }

                    break;

                case "--tailscale-exe":
                    if (!TryTakeValue(args, ref i, inlineValue, name, out tailscaleExecutable, out error))
                    {
                        return false;
                    }

                    break;

                case "--tailscale-check":
                    checkOnly = true;
                    break;

                default:
                    error = $"Unknown option '{arg}'.";
                    return false;
            }
        }

        if (showHelp)
        {
            options = new ServerOptions { ShowHelp = true };
            return true;
        }

        var tailscaleOptionSeen = tailscale || servePort != DefaultServePort || allowedLogins.Count > 0
            || auditFilePath is not null || tailscaleExecutable is not null || checkOnly || !verifyIdentity;

        if (tailscale)
        {
            // Tailscale mode is loopback-only by construction: Serve terminates TLS and forwards to us on loopback,
            // so binding anything else would open a second, unauthenticated door.
            if (hostSpecified)
            {
                error = "--host cannot be combined with --tailscale; Tailscale mode always binds loopback.";
                return false;
            }

            if (allowedLogins.Count == 0)
            {
                error = "--tailscale requires at least one --allow <login> so only named tailnet users can control this desktop.";
                return false;
            }

            transport = ServerTransport.Http;
        }
        else if (tailscaleOptionSeen)
        {
            error = "--serve-port, --allow, --verify-identity, --audit-file, --tailscale-exe, and --tailscale-check require --tailscale.";
            return false;
        }

        if (transport == ServerTransport.Stdio && httpOptionSeen)
        {
            error = "--host, --port, and --path only apply with --transport http.";
            return false;
        }

        if (transport == ServerTransport.Http)
        {
            if (!IsValidHost(host))
            {
                error = $"Invalid host '{host}'. Use an IP address or \"localhost\"; host names are not resolved.";
                return false;
            }

            if (!path.StartsWith('/') || path.Length < 2 || path.EndsWith('/') || path.Contains(' ', StringComparison.Ordinal))
            {
                error = $"Invalid path '{path}'. It must start with '/' and name a route without a trailing slash, e.g. /mcp.";
                return false;
            }

            if (port == 0 && string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
            {
                // Two loopback families with port 0 would get two different ports; make the caller pick one address.
                error = "--port 0 needs a single address. Use --host 127.0.0.1 or --host ::1 instead of localhost.";
                return false;
            }
        }

        options = new ServerOptions
        {
            Transport = transport,
            Host = host,
            Port = port,
            Path = path,
            Tailscale = tailscale,
            ServePort = servePort,
            AllowedLogins = allowedLogins,
            VerifyIdentity = verifyIdentity,
            AuditFilePath = auditFilePath,
            TailscaleExecutable = tailscaleExecutable,
            CheckOnly = checkOnly,
        };
        return true;
    }

    private static bool TryParseTransport(string value, out ServerTransport transport)
    {
        switch (value.Trim().ToLowerInvariant())
        {
            case "stdio":
                transport = ServerTransport.Stdio;
                return true;
            case "http":
                transport = ServerTransport.Http;
                return true;
            default:
                transport = ServerTransport.Stdio;
                return false;
        }
    }

    private static bool IsValidHost(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
        || IPAddress.TryParse(host, out _);

    private static (string Name, string? InlineValue) SplitInlineValue(string arg)
    {
        // Accept both "--port 8765" and "--port=8765".
        var separator = arg.IndexOf('=', StringComparison.Ordinal);
        return separator > 0 && arg.StartsWith("--", StringComparison.Ordinal)
            ? (arg[..separator], arg[(separator + 1)..])
            : (arg, null);
    }

    private static bool TryTakeValue(string[] args, ref int index, string? inlineValue, string name, out string value, out string? error)
    {
        error = null;
        if (inlineValue is not null)
        {
            value = inlineValue;
            return true;
        }

        if (index + 1 < args.Length && !args[index + 1].StartsWith("--", StringComparison.Ordinal))
        {
            index++;
            value = args[index];
            return true;
        }

        value = "";
        error = $"{name} requires a value.";
        return false;
    }
}

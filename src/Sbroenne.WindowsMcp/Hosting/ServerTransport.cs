namespace Sbroenne.WindowsMcp.Hosting;

/// <summary>
/// The transport the server uses to talk to its MCP client.
/// </summary>
public enum ServerTransport
{
    /// <summary>JSON-RPC over stdin/stdout. The default, used by VS Code, Claude Code, and the plugin.</summary>
    Stdio,

    /// <summary>Streamable HTTP served by Kestrel. Bound to loopback unless a host is given explicitly.</summary>
    Http,
}

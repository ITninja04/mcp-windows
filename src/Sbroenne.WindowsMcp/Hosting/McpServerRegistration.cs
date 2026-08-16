using Microsoft.Extensions.DependencyInjection;
using Sbroenne.WindowsMcp.Prompts;
using Sbroenne.WindowsMcp.Resources;

namespace Sbroenne.WindowsMcp.Hosting;

/// <summary>
/// Registers the MCP server the same way for every transport, so stdio and HTTP expose an identical
/// tool, prompt, and resource surface. Only the transport call differs at the call site.
/// </summary>
internal static class McpServerRegistration
{
    /// <summary>
    /// Adds the Windows MCP server with its tools, prompts, and resources. The caller chains the transport.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="serverVersion">Semver reported in the MCP handshake.</param>
    /// <returns>The server builder, ready for <c>WithStdioServerTransport()</c> or <c>WithHttpTransport()</c>.</returns>
    public static IMcpServerBuilder AddWindowsMcpServer(this IServiceCollection services, string serverVersion)
    {
        return services
            .AddMcpServer(options =>
            {
                options.ServerInfo = new()
                {
                    Name = "sbroenne.windows-mcp",
                    Version = serverVersion,
                };
                options.ServerInstructions = WindowsAutomationGuidance.ServerInstructions;
            })
            .WithToolsFromAssembly(typeof(McpServerRegistration).Assembly)  // Discovers static tools marked with [McpServerToolType]
            .WithPrompts<WindowsAutomationPrompts>()
            .WithResources<SystemResources>();
    }
}

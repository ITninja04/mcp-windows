using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sbroenne.WindowsMcp.Tools;

namespace Sbroenne.WindowsMcp.Tests.Integration;

/// <summary>
/// Starts the server with <c>--transport http</c> and speaks Streamable HTTP to it. These tests never call a
/// tool, so they need no desktop and run anywhere the stdio contract test runs.
/// </summary>
public sealed partial class HttpTransportTests
{
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task HttpTransport_ExposesSameToolsAsStdio()
    {
        using var cancellationSource = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var cancellationToken = cancellationSource.Token;

        using var stdio = StartServer([]);
        using var http = StartServer(["--transport", "http", "--port", "0"]);
        try
        {
            var endpoint = await ReadListeningUrlAsync(http, cancellationToken);
            Assert.StartsWith("http://127.0.0.1:", endpoint, StringComparison.Ordinal);
            Assert.EndsWith("/mcp", endpoint, StringComparison.Ordinal);

            using var client = new HttpClient();
            var initialize = await PostAsync(client, endpoint, 1, "initialize", new
            {
                protocolVersion = "2025-06-18",
                capabilities = new { },
                clientInfo = new { name = "http-transport-test", version = "1.0" }
            }, cancellationToken);
            Assert.Equal("sbroenne.windows-mcp", initialize.GetProperty("result").GetProperty("serverInfo").GetProperty("name").GetString());

            var httpTools = await PostAsync(client, endpoint, 2, "tools/list", new { }, cancellationToken);
            var httpNames = ToolNames(httpTools);

            await SendStdioAsync(stdio, 1, "initialize", new
            {
                protocolVersion = "2024-11-05",
                capabilities = new { },
                clientInfo = new { name = "http-transport-test", version = "1.0" }
            }, cancellationToken);
            _ = await ReadStdioResponseAsync(stdio, 1, cancellationToken);
            await SendStdioAsync(stdio, 2, "tools/list", new { }, cancellationToken);
            var stdioNames = ToolNames(await ReadStdioResponseAsync(stdio, 2, cancellationToken));

            Assert.NotEmpty(httpNames);
            Assert.Equal(stdioNames, httpNames);
        }
        finally
        {
            KillQuietly(http);
            KillQuietly(stdio);
        }
    }

    [Fact]
    public async Task HttpTransport_DefaultBindIsLoopbackAndIgnoresEnvironmentUrls()
    {
        using var cancellationSource = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var cancellationToken = cancellationSource.Token;

        // A hostile ASPNETCORE_URLS must not add a listener: the server binds only what --host asked for.
        using var http = StartServer(["--transport", "http", "--port", "0"], environment: new()
        {
            ["ASPNETCORE_URLS"] = "http://0.0.0.0:0",
        });
        try
        {
            var endpoint = await ReadListeningUrlAsync(http, cancellationToken);
            var uri = new Uri(endpoint);
            Assert.True(IPAddress.IsLoopback(IPAddress.Parse(uri.Host)));

            using var client = new HttpClient();
            var response = await client.GetAsync(endpoint, cancellationToken);
            // Any HTTP answer at all proves the loopback listener is up; GET on the MCP endpoint is not a
            // valid Streamable HTTP request, so the status is a client error rather than 200.
            Assert.True((int)response.StatusCode is >= 400 and < 500 or 200, $"Unexpected status {(int)response.StatusCode}");
        }
        finally
        {
            KillQuietly(http);
        }
    }

    [Fact]
    public async Task HttpTransport_RejectsForeignHostAndOrigin()
    {
        using var cancellationSource = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var cancellationToken = cancellationSource.Token;

        using var http = StartServer(["--transport", "http", "--port", "0"]);
        try
        {
            var endpoint = await ReadListeningUrlAsync(http, cancellationToken);
            using var client = new HttpClient();

            // A DNS-rebinding page reaches loopback with its own Host header; a browser adds Origin.
            using var foreignHost = new HttpRequestMessage(HttpMethod.Get, endpoint.Replace("/mcp", "/healthz", StringComparison.Ordinal));
            foreignHost.Headers.Host = "evil.example";
            using var foreignHostResponse = await client.SendAsync(foreignHost, cancellationToken);
            Assert.Equal(HttpStatusCode.Forbidden, foreignHostResponse.StatusCode);

            using var foreignOrigin = new HttpRequestMessage(HttpMethod.Get, endpoint.Replace("/mcp", "/healthz", StringComparison.Ordinal));
            foreignOrigin.Headers.Add("Origin", "http://evil.example");
            using var foreignOriginResponse = await client.SendAsync(foreignOrigin, cancellationToken);
            Assert.Equal(HttpStatusCode.Forbidden, foreignOriginResponse.StatusCode);

            using var healthResponse = await client.GetAsync(endpoint.Replace("/mcp", "/healthz", StringComparison.Ordinal), cancellationToken);
            Assert.Equal(HttpStatusCode.OK, healthResponse.StatusCode);
            Assert.Contains("\"status\":\"ok\"", await healthResponse.Content.ReadAsStringAsync(cancellationToken), StringComparison.Ordinal);
        }
        finally
        {
            KillQuietly(http);
        }
    }

    [Theory]
    [InlineData("--transport bogus")]
    [InlineData("--port 8765")]
    [InlineData("--transport http --host example.com")]
    public async Task InvalidArguments_ExitWithUsageError(string commandLine)
    {
        ArgumentNullException.ThrowIfNull(commandLine);
        using var cancellationSource = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var process = StartServer(commandLine.Split(' '));

        await process.WaitForExitAsync(cancellationSource.Token);
        var stderr = await process.StandardError.ReadToEndAsync(cancellationSource.Token);

        Assert.Equal(2, process.ExitCode);
        Assert.Contains("Usage:", stderr, StringComparison.Ordinal);
    }

    private static Process StartServer(string[] args, Dictionary<string, string>? environment = null)
    {
        var serverDllPath = typeof(WindowManagementTool).Assembly.Location;
        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add(serverDllPath);
        foreach (var arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }

        foreach (var (key, value) in environment ?? [])
        {
            startInfo.Environment[key] = value;
        }

        var process = new Process { StartInfo = startInfo };
        Assert.True(process.Start(), "Failed to start MCP server process.");
        return process;
    }

    private static async Task<string> ReadListeningUrlAsync(Process process, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(StartupTimeout);
        while (true)
        {
            var line = await process.StandardOutput.ReadLineAsync(timeout.Token);
            if (line is null)
            {
                var stderr = await process.StandardError.ReadToEndAsync(cancellationToken);
                Assert.Fail("Server exited before announcing its endpoint: " + stderr);
            }

            var match = ListeningUrlPattern().Match(line);
            if (match.Success)
            {
                return match.Groups["url"].Value;
            }
        }
    }

    private static async Task<JsonElement> PostAsync(HttpClient client, string endpoint, int id, string method, object parameters, CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Serialize(new { jsonrpc = "2.0", id, method, @params = parameters });
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));

        using var response = await client.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"{method} returned {(int)response.StatusCode}: {body}");

        // Streamable HTTP answers a POST either as plain JSON or as an SSE stream whose last data line is the response.
        var json = response.Content.Headers.ContentType?.MediaType == "text/event-stream"
            ? body.Split('\n').Where(l => l.StartsWith("data:", StringComparison.Ordinal)).Select(l => l[5..].Trim()).Last()
            : body;
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    private static async Task SendStdioAsync(Process process, int id, string method, object parameters, CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Serialize(new { jsonrpc = "2.0", id, method, @params = parameters });
        await process.StandardInput.WriteLineAsync(payload.AsMemory(), cancellationToken);
        await process.StandardInput.FlushAsync(cancellationToken);
    }

    private static async Task<JsonElement> ReadStdioResponseAsync(Process process, int id, CancellationToken cancellationToken)
    {
        while (true)
        {
            var line = await process.StandardOutput.ReadLineAsync(cancellationToken);
            Assert.NotNull(line);
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            using var document = JsonDocument.Parse(line);
            if (document.RootElement.TryGetProperty("id", out var responseId) &&
                responseId.TryGetInt32(out var value) &&
                value == id)
            {
                return document.RootElement.Clone();
            }
        }
    }

    private static List<string> ToolNames(JsonElement response) =>
        response.GetProperty("result").GetProperty("tools")
            .EnumerateArray()
            .Select(tool => tool.GetProperty("name").GetString()!)
            .Order(StringComparer.Ordinal)
            .ToList();

    private static void KillQuietly(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
            // Already gone.
        }
    }

    [GeneratedRegex(@"listening on (?<url>http://\S+)")]
    private static partial Regex ListeningUrlPattern();
}

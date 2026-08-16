using System.Net;
using Sbroenne.WindowsMcp.Hosting;

namespace Sbroenne.WindowsMcp.Tests.Unit;

public sealed class ServerOptionsTests
{
    [Fact]
    public void TryParse_NoArguments_DefaultsToStdio()
    {
        var parsed = ServerOptions.TryParse([], out var options, out var error);

        Assert.True(parsed);
        Assert.Null(error);
        Assert.Equal(ServerTransport.Stdio, options.Transport);
        Assert.False(options.ShowHelp);
    }

    [Fact]
    public void TryParse_TransportHttp_UsesLoopbackDefaults()
    {
        var parsed = ServerOptions.TryParse(["--transport", "http"], out var options, out _);

        Assert.True(parsed);
        Assert.Equal(ServerTransport.Http, options.Transport);
        Assert.Equal(ServerOptions.DefaultHttpHost, options.Host);
        Assert.Equal(ServerOptions.DefaultHttpPort, options.Port);
        Assert.Equal(ServerOptions.DefaultHttpPath, options.Path);
        Assert.True(options.BindsLoopbackOnly);
        Assert.Equal([IPAddress.Loopback], options.ListenAddresses);
    }

    [Fact]
    public void TryParse_InlineValues_AreAccepted()
    {
        var parsed = ServerOptions.TryParse(["--transport=http", "--port=9000", "--path=/windows"], out var options, out _);

        Assert.True(parsed);
        Assert.Equal(9000, options.Port);
        Assert.Equal("/windows", options.Path);
    }

    [Fact]
    public void TryParse_Tailscale_ImpliesLoopbackHttpAndKeepsAllowList()
    {
        var parsed = ServerOptions.TryParse(
            ["--tailscale", "--allow", "ozzie@github", "--allow", "someone@example.com", "--serve-port", "8443", "--no-verify-identity"],
            out var options,
            out var error);

        Assert.True(parsed);
        Assert.Null(error);
        Assert.True(options.Tailscale);
        Assert.Equal(ServerTransport.Http, options.Transport);
        Assert.True(options.BindsLoopbackOnly);
        Assert.Equal(8443, options.ServePort);
        Assert.False(options.VerifyIdentity);
        Assert.Equal(["ozzie@github", "someone@example.com"], options.AllowedLogins);
    }

    [Fact]
    public void TryParse_Version_IsAcceptedAnywhere()
    {
        var parsed = ServerOptions.TryParse(["--transport", "http", "--version"], out var options, out var error);

        Assert.True(parsed);
        Assert.Null(error);
        Assert.True(options.ShowVersion);
    }

    [Fact]
    public void TryParse_Localhost_ListensOnBothLoopbackFamilies()
    {
        var parsed = ServerOptions.TryParse(["--transport", "http", "--host", "localhost"], out var options, out _);

        Assert.True(parsed);
        Assert.True(options.BindsLoopbackOnly);
        Assert.Equal([IPAddress.Loopback, IPAddress.IPv6Loopback], options.ListenAddresses);
    }

    [Fact]
    public void TryParse_NonLoopbackHost_IsAcceptedButNotLoopback()
    {
        var parsed = ServerOptions.TryParse(["--transport", "http", "--host", "0.0.0.0"], out var options, out _);

        Assert.True(parsed);
        Assert.False(options.BindsLoopbackOnly);
        Assert.Equal([IPAddress.Any], options.ListenAddresses);
    }

    [Fact]
    public void TryParse_Help_ShortCircuitsEverythingElse()
    {
        var parsed = ServerOptions.TryParse(["--transport", "http", "--port", "1", "-h"], out var options, out var error);

        // --help wins over everything else that parsed, so no HTTP validation runs and no host is bound.
        Assert.True(parsed);
        Assert.Null(error);
        Assert.True(options.ShowHelp);
    }

    [Theory]
    [InlineData("--transport bogus", "Unknown transport")]
    [InlineData("--transport", "requires a value")]
    [InlineData("--port 8765", "only apply with --transport http")]
    [InlineData("--transport http --port 70000", "Invalid port")]
    [InlineData("--transport http --port -1", "Invalid port")]
    [InlineData("--transport http --host example.com", "Invalid host")]
    [InlineData("--transport http --path mcp", "Invalid path")]
    [InlineData("--transport http --path /", "Invalid path")]
    [InlineData("--transport http --path //", "Invalid path")]
    [InlineData("--transport http --path /mcp/", "Invalid path")]
    [InlineData("--transport http --host localhost --port 0", "single address")]
    [InlineData("--frobnicate", "Unknown option")]
    [InlineData("--tailscale", "requires at least one --allow")]
    [InlineData("--tailscale --allow me@github --host 127.0.0.1", "--host cannot be combined")]
    [InlineData("--serve-port 8443", "require --tailscale")]
    [InlineData("--allow me@github", "require --tailscale")]
    [InlineData("--transport http --allow me@github", "require --tailscale")]
    [InlineData("--tailscale --allow me@github --funnel", "funnel is not supported")]
    [InlineData("--funnel", "funnel is not supported")]
    [InlineData("--tailscale --allow me@github --serve-port 0", "Invalid serve port")]
    public void TryParse_InvalidArguments_FailWithReason(string commandLine, string expectedFragment)
    {
        ArgumentNullException.ThrowIfNull(commandLine);

        var parsed = ServerOptions.TryParse(commandLine.Split(' '), out _, out var error);

        Assert.False(parsed);
        Assert.NotNull(error);
        Assert.Contains(expectedFragment, error, StringComparison.Ordinal);
    }

    [Fact]
    public void Usage_MentionsEveryOption()
    {
        foreach (var option in new[] { "--transport", "--host", "--port", "--path", "--version", "--help" })
        {
            Assert.Contains(option, ServerOptions.Usage, StringComparison.Ordinal);
        }
    }
}

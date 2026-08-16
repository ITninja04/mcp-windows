using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;
using Sbroenne.WindowsMcp.Hosting;
using Sbroenne.WindowsMcp.Tailscale;

namespace Sbroenne.WindowsMcp.Tests.Unit;

public sealed class TailscaleIdentityMiddlewareTests
{
    private const string Login = "ITninja04@github";
    private const string PeerAddress = "100.64.0.9";
    private const string NodeName = "laptop.taila0594.ts.net";

    [Fact]
    public async Task InvokeAsync_RefusesNonLoopbackRemoteAddress()
    {
        var cli = CreateCli();
        var context = CreateContext(remoteAddress: IPAddress.Parse("192.168.0.50"));
        var called = false;

        var middleware = CreateMiddleware(cli, _ => { called = true; return Task.CompletedTask; });
        await middleware.InvokeAsync(context);

        Assert.False(called);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        await cli.DidNotReceiveWithAnyArgs().WhoisAsync(default!, default);
    }

    [Fact]
    public async Task InvokeAsync_RefusesMissingLoginHeader()
    {
        var cli = CreateCli();
        var context = CreateContext(login: null);
        var called = false;

        var middleware = CreateMiddleware(cli, _ => { called = true; return Task.CompletedTask; });
        await middleware.InvokeAsync(context);

        Assert.False(called);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_RefusesDuplicateLoginHeaders()
    {
        var cli = CreateCli();
        var context = CreateContext(login: null);
        context.Request.Headers[TailscaleIdentity.TailscaleUserLoginHeader] = new StringValues([Login, "attacker@github"]);
        var called = false;

        var middleware = CreateMiddleware(cli, _ => { called = true; return Task.CompletedTask; });
        await middleware.InvokeAsync(context);

        Assert.False(called);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_RefusesLoginOutsideAllowList()
    {
        var cli = CreateCli();
        var context = CreateContext(login: "someone-else@github");
        var called = false;

        var middleware = CreateMiddleware(cli, _ => { called = true; return Task.CompletedTask; });
        await middleware.InvokeAsync(context);

        Assert.False(called);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        await cli.DidNotReceiveWithAnyArgs().WhoisAsync(default!, default);
    }

    [Fact]
    public async Task InvokeAsync_RefusesWhenForwardedForIsMissing()
    {
        var cli = CreateCli();
        var context = CreateContext(forwardedFor: null);
        var called = false;

        var middleware = CreateMiddleware(cli, _ => { called = true; return Task.CompletedTask; });
        await middleware.InvokeAsync(context);

        Assert.False(called);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        await cli.DidNotReceiveWithAnyArgs().WhoisAsync(default!, default);
    }

    [Fact]
    public async Task InvokeAsync_RefusesWhenForwardedForIsNotAnAddress()
    {
        var cli = CreateCli();
        var context = CreateContext(forwardedFor: "not-an-address");
        var called = false;

        var middleware = CreateMiddleware(cli, _ => { called = true; return Task.CompletedTask; });
        await middleware.InvokeAsync(context);

        Assert.False(called);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_RefusesWhenWhoisFails()
    {
        var cli = Substitute.For<ITailscaleCli>();
        cli.WhoisAsync(Arg.Any<IPAddress>(), Arg.Any<CancellationToken>()).Returns((TailscaleWhois?)null);
        var context = CreateContext();
        var called = false;

        var middleware = CreateMiddleware(cli, _ => { called = true; return Task.CompletedTask; });
        await middleware.InvokeAsync(context);

        Assert.False(called);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_RefusesWhenWhoisThrows()
    {
        var cli = Substitute.For<ITailscaleCli>();
        cli.WhoisAsync(Arg.Any<IPAddress>(), Arg.Any<CancellationToken>())
            .Returns<Task<TailscaleWhois?>>(_ => throw new InvalidOperationException("tailscale.exe is missing"));
        var context = CreateContext();
        var called = false;

        var middleware = CreateMiddleware(cli, _ => { called = true; return Task.CompletedTask; });
        await middleware.InvokeAsync(context);

        Assert.False(called);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_RefusesWhenWhoisLoginDoesNotMatchHeader()
    {
        var cli = CreateCli(new TailscaleWhois("someone-else@github", "Someone Else", NodeName, []));
        var context = CreateContext();
        var called = false;

        var middleware = CreateMiddleware(cli, _ => { called = true; return Task.CompletedTask; });
        await middleware.InvokeAsync(context);

        Assert.False(called);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_RefusesTaggedNodeWithNoUserIdentity()
    {
        var cli = CreateCli(new TailscaleWhois(string.Empty, null, "ci-runner.taila0594.ts.net", ["tag:ci"]));
        var context = CreateContext();
        var called = false;

        var middleware = CreateMiddleware(cli, _ => { called = true; return Task.CompletedTask; });
        await middleware.InvokeAsync(context);

        Assert.False(called);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_SetsUserAndCallsNextOnVerifiedRequest()
    {
        var cli = CreateCli();
        var context = CreateContext();
        ClaimsPrincipal? seen = null;

        var middleware = CreateMiddleware(cli, inner => { seen = inner.User; return Task.CompletedTask; });
        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.NotNull(seen);
        Assert.True(seen.Identity?.IsAuthenticated);
        Assert.Equal(Login, seen.Identity?.Name);
        Assert.Equal(Login, seen.FindFirst(TailscaleIdentity.LoginClaimType)?.Value);
        Assert.Equal(NodeName, seen.FindFirst(TailscaleIdentity.NodeClaimType)?.Value);
        Assert.Equal(TailscaleIdentity.AuthenticationScheme, seen.Identity?.AuthenticationType);
    }

    [Fact]
    public async Task InvokeAsync_ReusesWhoisResultWithinTheCacheWindow()
    {
        var cli = CreateCli();
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-08-16T10:00:00Z", null));
        var middleware = CreateMiddleware(cli, _ => Task.CompletedTask, clock);

        await middleware.InvokeAsync(CreateContext());
        clock.Advance(TimeSpan.FromSeconds(5));
        var second = CreateContext();
        await middleware.InvokeAsync(second);

        Assert.Equal(StatusCodes.Status200OK, second.Response.StatusCode);
        await cli.Received(1).WhoisAsync(Arg.Any<IPAddress>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_QueriesWhoisAgainAfterTheCacheExpires()
    {
        var cli = CreateCli();
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-08-16T10:00:00Z", null));
        var middleware = CreateMiddleware(cli, _ => Task.CompletedTask, clock);

        await middleware.InvokeAsync(CreateContext());
        clock.Advance(TailscaleIdentityMiddleware.WhoisCacheLifetime + TimeSpan.FromSeconds(1));
        var second = CreateContext();
        await middleware.InvokeAsync(second);

        Assert.Equal(StatusCodes.Status200OK, second.Response.StatusCode);
        await cli.Received(2).WhoisAsync(Arg.Any<IPAddress>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvokeAsync_RefusesRatherThanServingAStaleCacheEntryWhenWhoisStartsFailing()
    {
        var cli = Substitute.For<ITailscaleCli>();
        cli.WhoisAsync(Arg.Any<IPAddress>(), Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromResult<TailscaleWhois?>(new TailscaleWhois(Login, "Ozzie", NodeName, [])), _ => Task.FromResult<TailscaleWhois?>(null));
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-08-16T10:00:00Z", null));
        var middleware = CreateMiddleware(cli, _ => Task.CompletedTask, clock);

        await middleware.InvokeAsync(CreateContext());
        clock.Advance(TailscaleIdentityMiddleware.WhoisCacheLifetime + TimeSpan.FromSeconds(1));
        var second = CreateContext();
        await middleware.InvokeAsync(second);

        Assert.Equal(StatusCodes.Status403Forbidden, second.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_SkipsWhoisWhenIdentityVerificationIsDisabled()
    {
        var cli = CreateCli();
        var context = CreateContext(forwardedFor: null);
        ClaimsPrincipal? seen = null;

        var options = CreateOptions() with { VerifyIdentity = false };
        var middleware = new TailscaleIdentityMiddleware(
            inner => { seen = inner.User; return Task.CompletedTask; },
            cli,
            options,
            new FakeTimeProvider(),
            NullLogger<TailscaleIdentityMiddleware>.Instance);
        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Equal(Login, seen?.Identity?.Name);
        await cli.DidNotReceiveWithAnyArgs().WhoisAsync(default!, default);
    }

    [Fact]
    public async Task InvokeAsync_ForbiddenBodyDoesNotEchoTheSuppliedHeaderValue()
    {
        const string Injected = "attacker-supplied-marker@evil";
        var cli = CreateCli();
        var context = CreateContext(login: Injected);

        var middleware = CreateMiddleware(cli, _ => Task.CompletedTask);
        await middleware.InvokeAsync(context);

        var body = await ReadBodyAsync(context);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        Assert.Equal(TailscaleIdentity.ForbiddenBody, body);
        Assert.DoesNotContain("attacker", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("evil", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task InvokeAsync_UsesTheRightmostForwardedForEntry()
    {
        var cli = CreateCli();
        var context = CreateContext(forwardedFor: $"203.0.113.7, {PeerAddress}");

        var middleware = CreateMiddleware(cli, _ => Task.CompletedTask);
        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        await cli.Received(1).WhoisAsync(IPAddress.Parse(PeerAddress), Arg.Any<CancellationToken>());
    }

    private static ITailscaleCli CreateCli(TailscaleWhois? whois = null)
    {
        var cli = Substitute.For<ITailscaleCli>();
        cli.WhoisAsync(Arg.Any<IPAddress>(), Arg.Any<CancellationToken>())
            .Returns(whois ?? new TailscaleWhois(Login, "Ozzie", NodeName, []));
        return cli;
    }

    private static ServerOptions CreateOptions() => new()
    {
        Transport = ServerTransport.Http,
        Tailscale = true,
        AllowedLogins = [Login],
        VerifyIdentity = true,
    };

    private static TailscaleIdentityMiddleware CreateMiddleware(
        ITailscaleCli cli,
        RequestDelegate next,
        TimeProvider? timeProvider = null) =>
        new(next, cli, CreateOptions(), timeProvider ?? new FakeTimeProvider(), NullLogger<TailscaleIdentityMiddleware>.Instance);

    private static DefaultHttpContext CreateContext(
        string? login = Login,
        string? forwardedFor = PeerAddress,
        IPAddress? remoteAddress = null)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = remoteAddress ?? IPAddress.Loopback;
        context.Response.Body = new MemoryStream();

        if (login is not null)
        {
            context.Request.Headers[TailscaleIdentity.TailscaleUserLoginHeader] = login;
        }

        if (forwardedFor is not null)
        {
            context.Request.Headers[TailscaleIdentity.ForwardedForHeader] = forwardedFor;
        }

        return context;
    }

    private static async Task<string> ReadBodyAsync(HttpContext context)
    {
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body, Encoding.UTF8, leaveOpen: true);
        return await reader.ReadToEndAsync();
    }
}

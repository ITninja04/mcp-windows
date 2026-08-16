using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Sbroenne.WindowsMcp.Hosting;

namespace Sbroenne.WindowsMcp.Tailscale;

/// <summary>
/// Refuses every HTTP request that does not carry a verified tailnet identity, and attaches that identity to
/// <see cref="HttpContext.User"/> for the tools and the audit log.
/// </summary>
/// <remarks>
/// <para>
/// Tailscale Serve terminates TLS on the tailnet and proxies to this process over loopback, adding the caller's
/// identity headers on the way. Two facts follow. First, the connection always looks like 127.0.0.1, so the
/// remote address proves only that the request did not arrive from the LAN. Second, the identity headers are
/// only trustworthy because Serve, not the caller, wrote them.
/// </para>
/// <para>
/// A local process could open the same loopback port and send the same headers by hand, so the login is
/// cross-checked against <c>tailscale whois</c> of the forwarded address. That check fails closed: any error,
/// timeout, missing header, or mismatch is a 403. Turning it off with --no-verify-identity reduces the
/// authentication to a header, which is why the option is discouraged.
/// </para>
/// </remarks>
public sealed partial class TailscaleIdentityMiddleware(
    RequestDelegate next,
    ITailscaleCli cli,
    ServerOptions options,
    TimeProvider timeProvider,
    ILogger<TailscaleIdentityMiddleware> logger)
{
    /// <summary>
    /// How long a successful whois answer is reused. Long enough that a burst of tool calls costs one process
    /// launch, short enough that revoking a device takes effect within seconds.
    /// </summary>
    public static readonly TimeSpan WhoisCacheLifetime = TimeSpan.FromSeconds(10);

    /// <summary>How long a single whois call may take before it counts as a failure.</summary>
    public static readonly TimeSpan WhoisTimeout = TimeSpan.FromSeconds(5);

    // A tailnet has far fewer peers than this; the cap only stops an unbounded dictionary if something goes wrong.
    private const int MaxCacheEntries = 256;

    private readonly RequestDelegate _next = next ?? throw new ArgumentNullException(nameof(next));
    private readonly ITailscaleCli _cli = cli ?? throw new ArgumentNullException(nameof(cli));
    private readonly ServerOptions _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ILogger<TailscaleIdentityMiddleware> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly Dictionary<IPAddress, WhoisCacheEntry> _whoisCache = [];
    private readonly Lock _cacheLock = new();

    /// <summary>
    /// Runs the identity checks for one request and either forwards it or answers 403.
    /// </summary>
    /// <param name="context">The request being handled.</param>
    /// <returns>A task that completes when the request has been handled.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var remoteAddress = context.Connection.RemoteIpAddress;
        if (remoteAddress is null || !IPAddress.IsLoopback(remoteAddress))
        {
            DeniedNonLoopback(remoteAddress?.ToString() ?? "unknown");
            await WriteForbiddenAsync(context);
            return;
        }

        if (!context.Request.Headers.TryGetValue(TailscaleIdentity.TailscaleUserLoginHeader, out var loginValues)
            || loginValues.Count != 1)
        {
            // More than one header means something between Serve and here added its own, so no value is trustworthy.
            DeniedLoginHeader(loginValues.Count);
            await WriteForbiddenAsync(context);
            return;
        }

        var login = loginValues[0];
        if (!TailscaleIdentity.IsPrintableIdentityValue(login))
        {
            DeniedLoginFormat();
            await WriteForbiddenAsync(context);
            return;
        }

        // The allowlist is checked before whois so an unknown login cannot make this process launch tailscale.exe.
        if (_options.AllowedLogins.Count > 0 && !IsAllowed(login))
        {
            DeniedNotAllowed(login);
            await WriteForbiddenAsync(context);
            return;
        }

        var nodeName = string.Empty;
        if (_options.VerifyIdentity)
        {
            var verified = await VerifyAsync(context, login);
            if (verified is null)
            {
                await WriteForbiddenAsync(context);
                return;
            }

            nodeName = verified;
        }

        context.User = BuildPrincipal(context, login, nodeName);
        Allowed(login);
        await _next(context);
    }

    /// <summary>
    /// Cross-checks the header login against <c>tailscale whois</c> of the forwarded address.
    /// </summary>
    /// <param name="context">The request being handled.</param>
    /// <param name="login">The login taken from the identity header.</param>
    /// <returns>The verified peer node name, or null when the request must be refused.</returns>
    private async Task<string?> VerifyAsync(HttpContext context, string login)
    {
        if (!TryReadForwardedFor(context, out var peerAddress))
        {
            DeniedForwardedFor(login);
            return null;
        }

        if (TryGetCachedLogin(peerAddress, out var cached) && MatchesLogin(cached.Login, login))
        {
            return cached.NodeName;
        }

        TailscaleWhois? whois;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            timeout.CancelAfter(WhoisTimeout);
            whois = await _cli.WhoisAsync(peerAddress, timeout.Token);
        }
        catch (OperationCanceledException)
        {
            DeniedWhoisFailed(login, peerAddress.ToString());
            return null;
        }
#pragma warning disable CA1031 // Any failure of an external process must fail closed, never fail open.
        catch (Exception exception)
        {
            WhoisThrew(exception, peerAddress.ToString());
            return null;
        }
#pragma warning restore CA1031

        if (whois is null)
        {
            DeniedWhoisFailed(login, peerAddress.ToString());
            return null;
        }

        if (whois.Tags.Count > 0 || string.IsNullOrEmpty(whois.LoginName))
        {
            // A tagged node has no user behind it, so there is no identity to audit or to match the allowlist.
            DeniedTaggedNode(peerAddress.ToString());
            return null;
        }

        if (!MatchesLogin(whois.LoginName, login))
        {
            DeniedLoginMismatch(login, whois.LoginName);
            return null;
        }

        var nodeName = TailscaleIdentity.IsPrintableIdentityValue(whois.NodeName) ? whois.NodeName : string.Empty;
        StoreCachedLogin(peerAddress, whois.LoginName, nodeName);
        return nodeName;
    }

    /// <summary>
    /// Reads the caller's tailnet address from the forwarded-for header.
    /// </summary>
    /// <param name="context">The request being handled.</param>
    /// <param name="address">The parsed address on success.</param>
    /// <returns>True when exactly one usable address could be read.</returns>
    /// <remarks>
    /// A caller may send its own X-Forwarded-For, in which case Serve appends the real address to the right of it.
    /// The rightmost entry is the one our own proxy wrote, so that is the only one used.
    /// </remarks>
    private static bool TryReadForwardedFor(HttpContext context, out IPAddress address)
    {
        address = IPAddress.None;
        if (!context.Request.Headers.TryGetValue(TailscaleIdentity.ForwardedForHeader, out var values) || values.Count == 0)
        {
            return false;
        }

        var last = values[values.Count - 1];
        if (string.IsNullOrWhiteSpace(last))
        {
            return false;
        }

        var separator = last.LastIndexOf(',');
        var candidate = (separator >= 0 ? last[(separator + 1)..] : last).Trim();
        return candidate.Length > 0 && candidate.Length <= 64 && IPAddress.TryParse(candidate, out address!);
    }

    private static bool MatchesLogin(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private bool IsAllowed(string login)
    {
        foreach (var allowed in _options.AllowedLogins)
        {
            if (MatchesLogin(allowed, login))
            {
                return true;
            }
        }

        return false;
    }

    private bool TryGetCachedLogin(IPAddress address, out WhoisCacheEntry entry)
    {
        var now = _timeProvider.GetUtcNow();
        lock (_cacheLock)
        {
            if (_whoisCache.TryGetValue(address, out entry) && entry.ExpiresAt > now)
            {
                return true;
            }

            // An expired entry is dropped rather than reused, so a whois that starts failing cannot be papered over.
            _whoisCache.Remove(address);
            return false;
        }
    }

    private void StoreCachedLogin(IPAddress address, string login, string nodeName)
    {
        var now = _timeProvider.GetUtcNow();
        lock (_cacheLock)
        {
            if (_whoisCache.Count >= MaxCacheEntries)
            {
                _whoisCache.Clear();
            }

            _whoisCache[address] = new WhoisCacheEntry(login, nodeName, now + WhoisCacheLifetime);
        }
    }

    private static ClaimsPrincipal BuildPrincipal(HttpContext context, string login, string nodeName)
    {
        var displayName = context.Request.Headers.TryGetValue(TailscaleIdentity.TailscaleUserNameHeader, out var nameValues)
            && nameValues.Count == 1
            && TailscaleIdentity.IsPrintableIdentityValue(nameValues[0])
                ? nameValues[0]!
                : login;

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, login),
            new(TailscaleIdentity.LoginClaimType, login),
            new(ClaimTypes.GivenName, displayName),
            new(TailscaleIdentity.NodeClaimType, nodeName),
        };

        return new ClaimsPrincipal(new ClaimsIdentity(claims, TailscaleIdentity.AuthenticationScheme, ClaimTypes.Name, ClaimTypes.Role));
    }

    private static Task WriteForbiddenAsync(HttpContext context)
    {
        // The body is a fixed string. Echoing any part of the request would hand an attacker a reflection point.
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = TailscaleIdentity.ForbiddenContentType;
        return context.Response.WriteAsync(TailscaleIdentity.ForbiddenBody);
    }

    [LoggerMessage(EventId = 4401, Level = LogLevel.Warning, Message = "Refused request from non-loopback address {RemoteAddress}.")]
    private partial void DeniedNonLoopback(string remoteAddress);

    [LoggerMessage(EventId = 4402, Level = LogLevel.Warning, Message = "Refused request carrying {HeaderCount} Tailscale-User-Login headers; exactly one is required.")]
    private partial void DeniedLoginHeader(int headerCount);

    [LoggerMessage(EventId = 4403, Level = LogLevel.Warning, Message = "Refused request whose Tailscale-User-Login header is empty, overlong, or not printable ASCII.")]
    private partial void DeniedLoginFormat();

    [LoggerMessage(EventId = 4404, Level = LogLevel.Warning, Message = "Refused login {Login}: not in the --allow list.")]
    private partial void DeniedNotAllowed(string login);

    [LoggerMessage(EventId = 4405, Level = LogLevel.Warning, Message = "Refused login {Login}: X-Forwarded-For is missing or is not an IP address.")]
    private partial void DeniedForwardedFor(string login);

    [LoggerMessage(EventId = 4406, Level = LogLevel.Warning, Message = "Refused login {Login}: tailscale whois {PeerAddress} failed or timed out.")]
    private partial void DeniedWhoisFailed(string login, string peerAddress);

    [LoggerMessage(EventId = 4407, Level = LogLevel.Warning, Message = "Refused peer {PeerAddress}: the node is tagged and has no user identity.")]
    private partial void DeniedTaggedNode(string peerAddress);

    [LoggerMessage(EventId = 4408, Level = LogLevel.Warning, Message = "Refused login {HeaderLogin}: tailscale whois reports {WhoisLogin} for that address.")]
    private partial void DeniedLoginMismatch(string headerLogin, string whoisLogin);

    [LoggerMessage(EventId = 4409, Level = LogLevel.Warning, Message = "Refused request: tailscale whois {PeerAddress} threw.")]
    private partial void WhoisThrew(Exception exception, string peerAddress);

    [LoggerMessage(EventId = 4410, Level = LogLevel.Debug, Message = "Accepted request from {Login}.")]
    private partial void Allowed(string login);

    /// <summary>One cached whois answer and the moment it stops being usable.</summary>
    /// <param name="Login">The login whois reported for the address.</param>
    /// <param name="NodeName">The peer node's MagicDNS name.</param>
    /// <param name="ExpiresAt">The instant after which the entry must be discarded.</param>
    private readonly record struct WhoisCacheEntry(string Login, string NodeName, DateTimeOffset ExpiresAt);
}

/// <summary>
/// Adds <see cref="TailscaleIdentityMiddleware"/> to an application pipeline.
/// </summary>
public static class TailscaleIdentityMiddlewareExtensions
{
    /// <summary>
    /// Requires a verified tailnet identity on every request handled after this point.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The same builder, for chaining.</returns>
    /// <remarks>
    /// Register this before the MCP endpoint and before anything else that can act on a request. Do not pair it
    /// with UseForwardedHeaders: that would rewrite the connection remote address and defeat the loopback check.
    /// </remarks>
    public static IApplicationBuilder UseTailscaleIdentity(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<TailscaleIdentityMiddleware>();
    }
}

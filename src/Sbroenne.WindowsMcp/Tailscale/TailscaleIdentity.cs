using System.Diagnostics.CodeAnalysis;

namespace Sbroenne.WindowsMcp.Tailscale;

/// <summary>
/// The header names, claim types, and labels used to carry a tailnet identity through the request pipeline.
/// </summary>
/// <remarks>
/// These strings appear in the middleware, in the audit filter, and in the tests. A typo in any one of them
/// would silently turn an authentication check into a no-op, so they are declared once, here.
/// </remarks>
public static class TailscaleIdentity
{
    /// <summary>Header Tailscale Serve injects with the caller's login, e.g. "user@github".</summary>
    public const string TailscaleUserLoginHeader = "Tailscale-User-Login";

    /// <summary>Header Tailscale Serve injects with the caller's display name.</summary>
    public const string TailscaleUserNameHeader = "Tailscale-User-Name";

    /// <summary>Header Tailscale Serve injects with a URL to the caller's profile picture.</summary>
    public const string TailscaleUserProfilePicHeader = "Tailscale-User-Profile-Pic";

    /// <summary>Header Tailscale Serve injects describing which identity headers it set.</summary>
    public const string TailscaleHeadersInfoHeader = "Tailscale-Headers-Info";

    /// <summary>
    /// Header Tailscale Serve injects with the caller's tailnet address.
    /// </summary>
    /// <remarks>
    /// This is read as a raw header on purpose. The forwarded-headers middleware would rewrite the connection
    /// remote address from it, which would make the loopback check pass for anyone who sends the header.
    /// </remarks>
    public const string ForwardedForHeader = "X-Forwarded-For";

    /// <summary>Claim type holding the peer node's MagicDNS name.</summary>
    public const string NodeClaimType = "tailscale:node";

    /// <summary>Claim type holding the caller's tailnet login, alongside the standard name claim.</summary>
    public const string LoginClaimType = "tailscale:login";

    /// <summary>Authentication type stamped on the identity, and the label used in logs.</summary>
    public const string AuthenticationScheme = "Tailscale";

    /// <summary>The entire body returned with a 403. It never echoes anything the caller sent.</summary>
    public const string ForbiddenBody = "{\"error\":\"forbidden\"}";

    /// <summary>Content type of <see cref="ForbiddenBody"/>.</summary>
    public const string ForbiddenContentType = "application/json";

    /// <summary>Longest identity string accepted from a header, well above any real tailnet login.</summary>
    public const int MaxIdentityValueLength = 256;

    /// <summary>
    /// Checks whether a header value is safe to treat as an identity: non-empty, not overlong, printable ASCII.
    /// </summary>
    /// <param name="value">The raw header value.</param>
    /// <returns>True when the value can be used as a login, display name, or node name.</returns>
    /// <remarks>
    /// Rejecting control characters here means nothing downstream, log lines included, can be split or spoofed
    /// by a caller who puts a newline in a header.
    /// </remarks>
    public static bool IsPrintableIdentityValue([NotNullWhen(true)] string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaxIdentityValueLength)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character is < ' ' or > '~')
            {
                return false;
            }
        }

        return true;
    }
}

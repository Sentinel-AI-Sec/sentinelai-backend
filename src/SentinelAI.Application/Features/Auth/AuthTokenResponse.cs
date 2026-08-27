namespace SentinelAI.Application.Features.Auth;

/// <summary>What Register, Login, and Refresh all hand back — a usable token pair.</summary>
public sealed record AuthTokenResponse
{
    public required string AccessToken { get; init; }
    public required DateTime AccessTokenExpiresAt { get; init; }
    public required string RefreshToken { get; init; }
    public required DateTime RefreshTokenExpiresAt { get; init; }
    public required Guid TenantId { get; init; }

    /// <summary>
    /// Who this token was issued to — the <c>sub</c> claim inside <see cref="AccessToken"/>,
    /// echoed for the same reason <see cref="TenantId"/> is: so a client can identify itself
    /// without decoding a JWT in the browser.
    /// </summary>
    /// <remarks>
    /// Not merely a convenience. The console needs it to tell its own row apart from everyone
    /// else's in the members table, because an admin may not change their own role — without
    /// this the screen would have to offer that action to find out it is refused.
    /// </remarks>
    public required Guid UserId { get; init; }

    public required string Role { get; init; }

    /// <summary>
    /// The scopes baked into <see cref="AccessToken"/>, echoed so a caller can see what the
    /// token can do without decoding it. Derived from <see cref="Role"/> — this is a readback,
    /// not a second source of truth.
    /// </summary>
    public required IReadOnlyList<string> Scopes { get; init; }
}

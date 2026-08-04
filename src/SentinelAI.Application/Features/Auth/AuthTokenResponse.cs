namespace SentinelAI.Application.Features.Auth;

/// <summary>What Register, Login, and Refresh all hand back — a usable token pair.</summary>
public sealed record AuthTokenResponse
{
    public required string AccessToken { get; init; }
    public required DateTime AccessTokenExpiresAt { get; init; }
    public required string RefreshToken { get; init; }
    public required DateTime RefreshTokenExpiresAt { get; init; }
    public required Guid TenantId { get; init; }
    public required string Role { get; init; }
}

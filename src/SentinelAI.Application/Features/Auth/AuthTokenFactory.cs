using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Auth;

/// <summary>
/// The one piece Register, Login, and Refresh all do identically: mint a token pair,
/// persist the refresh token's hash, hand back a response. Kept in one place so there's
/// exactly one spot that decides what a "successful auth" response looks like.
/// </summary>
public sealed class AuthTokenFactory(IUnitOfWork unitOfWork, IJwtTokenIssuer tokenIssuer)
{
    public async Task<AuthTokenResponse> IssueAsync(User user, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var accessToken = tokenIssuer.IssueAccessToken(user);
        var rawRefreshToken = tokenIssuer.GenerateRefreshToken();

        var refreshToken = new RefreshToken
        {
            Id = Guid.CreateVersion7(),
            TenantId = user.TenantId,
            UserId = user.Id,
            TokenHash = tokenIssuer.HashRefreshToken(rawRefreshToken),
            ExpiresAt = now.Add(tokenIssuer.RefreshTokenLifetime),
            CreatedAt = now,
        };

        await unitOfWork.Repository<RefreshToken>().AddAsync(refreshToken);
        await unitOfWork.CompleteAsync();

        return new AuthTokenResponse
        {
            AccessToken = accessToken,
            AccessTokenExpiresAt = now.Add(tokenIssuer.AccessTokenLifetime),
            RefreshToken = rawRefreshToken,
            RefreshTokenExpiresAt = refreshToken.ExpiresAt,
            TenantId = user.TenantId,
            UserId = user.Id,
            Role = user.Role,
            Scopes = RoleScopes.For(user.Role),
        };
    }
}

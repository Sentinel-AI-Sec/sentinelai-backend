using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Abstractions.Repositories;

/// <summary>
/// Mints credentials for a user. The counterpart to <see cref="ICallerContext"/>, which
/// only ever reads claims — this is the one place that writes them.
/// </summary>
public interface IJwtTokenIssuer
{
    /// <summary>A short-lived, signed access token carrying tenant_id/sub/role.</summary>
    string IssueAccessToken(User user);

    /// <summary>How long an issued access token is valid for.</summary>
    TimeSpan AccessTokenLifetime { get; }

    /// <summary>
    /// A long-lived, cryptographically random opaque secret — not a JWT, and carries no
    /// claims of its own. The caller is responsible for hashing it before persisting it
    /// (never store it raw, same principle as a password) and for looking the hash back up
    /// when it's presented to <c>/v1/auth/refresh</c>.
    /// </summary>
    string GenerateRefreshToken();

    /// <summary>How long an issued refresh token is valid for.</summary>
    TimeSpan RefreshTokenLifetime { get; }

    /// <summary>
    /// Hashes a refresh token for storage/lookup. Deliberately not
    /// <see cref="IPasswordHasher"/>: PBKDF2 salts randomly per call, so hashing the same
    /// input twice gives two different strings — correct for a low-entropy human password,
    /// but it means the result can never be looked up again by exact match, which is exactly
    /// how a refresh token has to be found at <c>/v1/auth/refresh</c>. A refresh token is
    /// already 64 random bytes; a deterministic hash is both correct here and cheaper.
    /// </summary>
    string HashRefreshToken(string rawToken);
}

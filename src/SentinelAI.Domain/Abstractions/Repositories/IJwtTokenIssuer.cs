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
    /// A long-lived, signed token for a machine — the GitHub Action, not a person.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Deliberately not <see cref="IssueAccessToken"/> with a longer expiry. A machine token
    /// carries <c>tenant_id</c> and a <c>scope</c> claim and <b>no <c>role</c> claim and no
    /// <c>sub</c></b>: every destructive endpoint is role-gated rather than scope-gated, so a
    /// token with no role is one that can upload a bundle and read the result back and can never
    /// purge anything, whatever it holds. That property is the whole reason this is a separate
    /// method — hand it a <see cref="User"/> and the role comes along with them.
    /// </para>
    /// <para>
    /// Nothing is persisted. Unlike a refresh token there is no stored hash to revoke against, so
    /// the only way to invalidate one before its expiry is to rotate
    /// <c>Authentication:Jwt:SigningKey</c>, which invalidates every token this API ever issued.
    /// Callers should treat what comes back as a secret they will not be shown again.
    /// </para>
    /// </remarks>
    /// <param name="tenantId">The tenant the token acts for — from the caller's verified token,
    /// never from a request body.</param>
    /// <param name="scopes">What the token may do. An empty list yields no <c>scope</c> claim at
    /// all rather than an empty one, for the reason given on <see cref="RoleScopes.ClaimValue"/>.</param>
    string IssueMachineToken(Guid tenantId, IReadOnlyList<string> scopes);

    /// <summary>How long an issued machine token is valid for
    /// (<c>Authentication:Jwt:MachineTokenDays</c>, default 365).</summary>
    TimeSpan MachineTokenLifetime { get; }

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

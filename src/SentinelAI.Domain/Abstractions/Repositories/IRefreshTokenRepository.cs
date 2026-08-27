using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Abstractions.Repositories;

public interface IRefreshTokenRepository
{
    /// <summary>
    /// Looks up a refresh token by its hash, across every tenant — same reasoning as
    /// <see cref="IUserRepository.GetByEmailAsync"/>: the token itself is the only thing
    /// presented at refresh/logout time, so which tenant it belongs to is what this
    /// determines, not something known beforehand.
    /// </summary>
    Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken ct = default);

    /// <summary>
    /// Revokes every live refresh token held by one user, whatever tenant they sit in, and
    /// returns how many were revoked. Already-revoked and expired rows are left alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Called whenever something changes what a user's next token should say — their role, or the
    /// tenant they belong to. Without it the change is inert for the refresh token's whole
    /// lifetime: the claims live in the token, nothing re-reads the row until one is reissued, and
    /// a demoted or moved account would keep renewing its old claims for thirty days.
    /// </para>
    /// <para>
    /// Tenant-agnostic on purpose. A member being moved between tenants still holds tokens
    /// stamped with the <em>old</em> tenant, which is precisely the set that must stop working and
    /// precisely the set the caller's filtered repository cannot see.
    /// </para>
    /// </remarks>
    Task<int> RevokeAllForUserAsync(Guid userId, DateTime revokedAt, CancellationToken ct = default);
}

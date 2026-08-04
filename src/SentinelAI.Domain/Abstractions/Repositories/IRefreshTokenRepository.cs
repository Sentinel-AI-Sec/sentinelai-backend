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
}

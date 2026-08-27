using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

public class RefreshTokenRepository(SentinelDbContext context) : IRefreshTokenRepository
{
    // Tracked, not AsNoTracking: refresh/logout both mutate the row they find (revoke it)
    // and save through the same context. IgnoreQueryFilters() applies to the whole query,
    // including the Include - the related User comes back unfiltered too, which is the
    // point: neither side is known to belong to any particular tenant until this lookup
    // resolves it.
    public async Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken ct = default)
        => await context.RefreshTokens
            .IgnoreQueryFilters() // see IRefreshTokenRepository.GetByTokenHashAsync
            .Include(r => r.User)
            .FirstOrDefaultAsync(r => r.TokenHash == tokenHash, ct);

    // Tracked and saved here rather than left for the caller's unit of work: the rows are found
    // through IgnoreQueryFilters, so a caller who forgot to save would leave a moved or demoted
    // account holding working credentials — the exact failure this method exists to prevent.
    // Already-revoked rows are skipped so a second call cannot rewrite the first one's timestamp,
    // which is what an audit reads to find out when access was actually withdrawn.
    public async Task<int> RevokeAllForUserAsync(
        Guid userId, DateTime revokedAt, CancellationToken ct = default)
    {
        var live = await context.RefreshTokens
            .IgnoreQueryFilters() // see IRefreshTokenRepository.RevokeAllForUserAsync
            .Where(r => r.UserId == userId && r.RevokedAt == null && r.ExpiresAt > revokedAt)
            .ToListAsync(ct);

        if (live.Count == 0) return 0;

        foreach (var token in live) token.RevokedAt = revokedAt;

        await context.SaveChangesAsync(ct);

        return live.Count;
    }
}

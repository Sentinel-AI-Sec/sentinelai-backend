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
}

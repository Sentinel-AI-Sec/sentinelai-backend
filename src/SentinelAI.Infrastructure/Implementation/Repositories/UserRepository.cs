using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

public class UserRepository(SentinelDbContext context) : IUserRepository
{
    public async Task<User?> GetByEmailAsync(string email, CancellationToken ct = default)
        => await context.Users
            .IgnoreQueryFilters() // see IUserRepository.GetByEmailAsync
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Email == email, ct);

    // One round trip rather than two counts: the two numbers are read together to decide a
    // single question ("what would this tenant be left with"), and reading them separately
    // invites the two halves drifting apart under a concurrent write.
    public async Task<TenantMembership> CountMembersAsync(Guid tenantId, CancellationToken ct = default)
    {
        var counts = await context.Users
            .IgnoreQueryFilters() // see IUserRepository.CountMembersAsync
            .AsNoTracking()
            .Where(u => u.TenantId == tenantId)
            .GroupBy(_ => 1)
            .Select(g => new
            {
                Total = g.Count(),
                Admins = g.Count(u => u.Role == Roles.Admin),
            })
            .FirstOrDefaultAsync(ct);

        // No rows means no group, not a zero row — an empty tenant is a real answer here (it is
        // what makes a tenant purgeable), so it is spelled out rather than left to a null deref.
        return counts is null
            ? new TenantMembership(0, 0)
            : new TenantMembership(counts.Total, counts.Admins);
    }
}

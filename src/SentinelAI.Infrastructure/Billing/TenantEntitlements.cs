using Microsoft.EntityFrameworkCore;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Infrastructure.Billing;

/// <summary>
/// Resolves a tenant's plan limits from <c>Tenant.PlanTier</c>.
/// </summary>
/// <remarks>
/// <para>
/// <c>Tenant</c> is keyed by <c>Id</c> and does not implement <c>ITenantOwned</c>, so it carries no
/// query filter and this works identically inside a request and from the pipeline worker, which has
/// no ambient tenant to be filtered by.
/// </para>
/// <para>
/// A tenant row that has gone missing resolves to the free tier rather than throwing. Every caller
/// is on a path that was doing something else — submitting a scan, deciding whether to run a debate
/// — and none of them should turn a lookup miss into a 500. Failing to the least privilege is also
/// the safe direction: the worst case is a customer briefly under-served, not a paywall bypassed.
/// </para>
/// </remarks>
public sealed class TenantEntitlements(SentinelDbContext context) : ITenantEntitlements
{
    public async Task<PlanEntitlements> ForTenantAsync(Guid tenantId, CancellationToken ct = default)
    {
        var tier = await context.Set<Tenant>()
            .AsNoTracking()
            .Where(t => t.Id == tenantId)
            .Select(t => t.PlanTier)
            .FirstOrDefaultAsync(ct);

        return PlanEntitlementCatalog.For(tier);
    }
}

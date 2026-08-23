using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Infrastructure.Billing;

/// <summary>
/// <see cref="IScanQuotaCounter"/> over the <c>ScanQuotaCounters</c> table.
/// </summary>
/// <remarks>
/// <para>
/// <b>The conditional UPDATE is the whole design.</b> One statement both tests the limit and spends
/// the unit — <c>UPDATE … SET Count = Count + 1 WHERE TenantId = @t AND UtcDay = @d AND Count &lt;
/// @limit</c> — so the database's own row lock serializes concurrent submissions. Its rows-affected
/// answers the question: 1 means the unit was taken, 0 means either the row is missing or the limit
/// was already reached, and those two are distinguished afterwards by a read that cannot race
/// anything (a counter never goes down).
/// </para>
/// <para>
/// Written with <c>ExecuteUpdateAsync</c> rather than raw SQL Server, unlike its neighbour
/// <c>SqlScanJobClaim</c>. That one needs <c>UPDATE … OUTPUT</c> with a CTE and has no portable
/// equivalent, so it is SQL-Server-only and the integration suite disables the worker that uses it.
/// A quota has to be exercised by tests — refusing the third scan is the behaviour under test — and
/// the suite runs on SQLite, so this stays in the provider-neutral subset. It compiles to a single
/// atomic statement on both.
/// </para>
/// <para>
/// <see cref="IgnoreQueryFilters"/> with an explicit tenant predicate, following
/// <c>TenantPurgeService</c>: this runs both inside a request and from the pipeline worker, and a
/// counter that silently matched nothing because the ambient tenant was unset would hand out
/// unlimited scans rather than failing.
/// </para>
/// </remarks>
public sealed class ScanQuotaCounterStore(SentinelDbContext context) : IScanQuotaCounter
{
    public async Task<QuotaDecision> TryConsumeAsync(
        Guid tenantId, int limit, DateOnly utcDay, CancellationToken ct = default)
    {
        // Unlimited plans never touch the table. Enterprise scanning in CI would otherwise write a
        // row per day forever to count something nobody reads.
        if (limit == int.MaxValue)
            return new QuotaDecision(Allowed: true, Used: 0, Limit: limit);

        if (limit <= 0)
            return new QuotaDecision(Allowed: false, Used: 0, Limit: limit);

        var taken = await Rows(tenantId, utcDay)
            .Where(c => c.Count < limit)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.Count, c => c.Count + 1), ct);

        if (taken > 0)
            return new QuotaDecision(true, await CountAsync(tenantId, utcDay, ct), limit);

        // Nothing updated: either today has no row yet, or the allowance is spent.
        if (await Rows(tenantId, utcDay).AnyAsync(ct))
            return new QuotaDecision(false, await CountAsync(tenantId, utcDay, ct), limit);

        try
        {
            context.Set<ScanQuotaCounter>().Add(new ScanQuotaCounter
            {
                Id = Guid.CreateVersion7(),
                TenantId = tenantId,
                UtcDay = utcDay,
                Count = 1,
            });

            await context.SaveChangesAsync(ct);

            return new QuotaDecision(true, 1, limit);
        }
        catch (DbUpdateException)
        {
            // Two first-of-the-day submissions raced and the unique index on (TenantId, UtcDay)
            // rejected the loser — which is the index doing its job, not an error. The row now
            // exists, so the conditional update that failed above will now succeed or refuse
            // honestly. Retried once and only once: a second failure is not a race.
            context.ChangeTracker.Clear();

            var retried = await Rows(tenantId, utcDay)
                .Where(c => c.Count < limit)
                .ExecuteUpdateAsync(s => s.SetProperty(c => c.Count, c => c.Count + 1), ct);

            return new QuotaDecision(retried > 0, await CountAsync(tenantId, utcDay, ct), limit);
        }
    }

    public async Task ReleaseAsync(Guid tenantId, DateOnly utcDay, CancellationToken ct = default) =>
        // Guarded at zero so a double release cannot drive the meter negative and hand out free
        // scans. Conditional in the statement, for the same reason the increment is.
        await Rows(tenantId, utcDay)
            .Where(c => c.Count > 0)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.Count, c => c.Count - 1), ct);

    public async Task<int> UsedTodayAsync(Guid tenantId, DateOnly utcDay, CancellationToken ct = default) =>
        await CountAsync(tenantId, utcDay, ct);

    private IQueryable<ScanQuotaCounter> Rows(Guid tenantId, DateOnly utcDay) =>
        context.Set<ScanQuotaCounter>()
            .IgnoreQueryFilters()
            .Where(c => c.TenantId == tenantId && c.UtcDay == utcDay);

    private async Task<int> CountAsync(Guid tenantId, DateOnly utcDay, CancellationToken ct) =>
        await Rows(tenantId, utcDay).Select(c => c.Count).FirstOrDefaultAsync(ct);
}

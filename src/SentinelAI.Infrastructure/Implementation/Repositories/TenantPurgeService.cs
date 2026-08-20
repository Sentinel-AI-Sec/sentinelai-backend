using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

/// <summary>
/// Deletes every row and every stored bundle belonging to one tenant (SEC-35).
/// </summary>
/// <remarks>
/// <para>
/// <b>Order is the whole difficulty.</b> Most foreign keys in this schema cascade, but
/// <c>ChainHop → Finding / Chain / GraphNode</c> and <c>GraphEdge → GraphNode</c> are configured
/// <see cref="DeleteBehavior.Restrict"/> — deliberately, because a chain hop pointing at a
/// finding that silently vanished is a corrupted audit trail. The consequence here is that
/// deleting in the obvious order (jobs first, let the cascades run) throws a foreign-key
/// violation partway through and leaves the account <em>half</em> deleted. For a feature whose
/// entire purpose is "your data is gone", partial success is the worst possible outcome.
/// </para>
/// <para>
/// So children are removed before parents, explicitly, in one transaction. The transaction is
/// what makes a mid-way failure a no-op rather than a half-purge: either the account is gone or
/// nothing changed and the caller can retry.
/// </para>
/// <para>
/// Query filters are ignored throughout and the tenant id is matched explicitly. The ambient
/// filter would usually agree — an admin deleting their own account resolves to the same tenant
/// — but relying on it here would mean the blast radius of this operation is decided by whoever
/// happens to hold the request context, and that is not a thing to leave implicit in a delete.
/// </para>
/// <para>
/// Bundles are purged from storage <em>before</em> the rows go. Once <c>ScanJob</c> is deleted
/// there is no record of which jobs existed, so a failure after that point would orphan files on
/// disk with nothing left pointing at them — deleted from the database and undeletable forever.
/// </para>
/// </remarks>
public sealed class TenantPurgeService(
    SentinelDbContext db,
    IBundleStore bundleStore,
    IBillingGateway billing,
    ILogger<TenantPurgeService> logger) : ITenantPurge
{
    public async Task<TenantPurgeReport> PurgeAsync(Guid tenantId, CancellationToken ct = default)
    {
        if (tenantId == Guid.Empty)
            throw new ArgumentException("A tenant id is required.", nameof(tenantId));

        // Stripe first, for the same reason storage goes before the rows: once this returns there
        // is no subscription row left to say a subscription existed, and nothing in this product
        // would ever look at it again. See CancelBillingAsync for why a failure here does not
        // abort the deletion.
        await CancelBillingAsync(tenantId, ct);

        // Storage first, while the job rows still say which bundles exist.
        var jobIds = await db.ScanJobs
            .IgnoreQueryFilters()
            .Where(j => j.TenantId == tenantId)
            .Select(j => j.Id)
            .ToListAsync(ct);

        foreach (var jobId in jobIds)
            await bundleStore.PurgeAsync(jobId, ct);

        var rows = new Dictionary<string, int>(StringComparer.Ordinal);

        // The in-memory provider used by tests has no transaction support; the real one does,
        // and this operation is exactly the kind that must not half-apply.
        var transaction = db.Database.IsRelational()
            ? await db.Database.BeginTransactionAsync(ct)
            : null;

        try
        {
            // Children first. Every step's targets are reachable only through this tenant's
            // rows, so nothing outside the tenant is touched.
            rows[nameof(Citation)] = await DeleteAsync<Citation>(tenantId, ct);
            rows[nameof(ChainHop)] = await DeleteAsync<ChainHop>(tenantId, ct);
            rows[nameof(GraphEdge)] = await DeleteAsync<GraphEdge>(tenantId, ct);
            rows[nameof(Chain)] = await DeleteAsync<Chain>(tenantId, ct);
            rows[nameof(Report)] = await DeleteAsync<Report>(tenantId, ct);
            rows[nameof(Finding)] = await DeleteAsync<Finding>(tenantId, ct);
            rows[nameof(GraphNode)] = await DeleteAsync<GraphNode>(tenantId, ct);
            rows[nameof(ScanBundle)] = await DeleteAsync<ScanBundle>(tenantId, ct);
            rows[nameof(ScanJob)] = await DeleteAsync<ScanJob>(tenantId, ct);
            rows[nameof(Project)] = await DeleteAsync<Project>(tenantId, ct);
            rows[nameof(RefreshToken)] = await DeleteAsync<RefreshToken>(tenantId, ct);
            rows[nameof(Subscription)] = await DeleteAsync<Subscription>(tenantId, ct);
            rows[nameof(User)] = await DeleteAsync<User>(tenantId, ct);

            // The tenant itself last: it is what everything above hung from.
            var tenant = await db.Tenants
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(t => t.Id == tenantId, ct);

            if (tenant is not null) db.Tenants.Remove(tenant);
            rows[nameof(Tenant)] = tenant is null ? 0 : 1;

            await db.SaveChangesAsync(ct);

            if (transaction is not null) await transaction.CommitAsync(ct);
        }
        catch
        {
            if (transaction is not null) await transaction.RollbackAsync(ct);
            throw;
        }
        finally
        {
            if (transaction is not null) await transaction.DisposeAsync();
        }

        var report = new TenantPurgeReport(rows, jobIds.Count);

        logger.LogWarning(
            "Account purge for tenant {TenantId}: {Rows} row(s) across {Tables} table(s) and "
            + "{Bundles} stored bundle(s) permanently deleted",
            tenantId, report.TotalRows, rows.Count, report.BundlesPurged);

        return report;
    }

    /// <summary>
    /// Marks every row of one tenant-owned entity for deletion and reports how many.
    /// </summary>
    /// <remarks>
    /// Entities are loaded and removed rather than deleted with <c>ExecuteDelete</c>. Bulk
    /// delete would be faster, but it bypasses the change tracker and cannot participate in the
    /// same unit of work as the tenant row above — and account volumes here are small enough
    /// that correctness is the only axis worth optimising.
    /// </remarks>
    private async Task<int> DeleteAsync<TEntity>(Guid tenantId, CancellationToken ct)
        where TEntity : class, Domain.Abstractions.ITenantOwned
    {
        var rows = await db.Set<TEntity>()
            .IgnoreQueryFilters()
            .Where(e => e.TenantId == tenantId)
            .ToListAsync(ct);

        if (rows.Count > 0) db.Set<TEntity>().RemoveRange(rows);
        return rows.Count;
    }

    /// <summary>
    /// Ends this tenant's Stripe subscription, if it has one, before its rows are destroyed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A failure here does not stop the deletion, and that is a deliberate ranking of two bad
    /// outcomes.</b> SEC-35's promise is that an account can be deleted; making that promise
    /// conditional on a third party being reachable would mean a Stripe outage — or a revoked API
    /// key on a deployment that has since stopped selling — leaves a customer unable to delete
    /// their own data. The other outcome is a card that keeps being charged for an account that
    /// no longer exists, which is why this is logged at error level with the subscription id: it
    /// is fixable by a human in the Stripe dashboard in under a minute, and that log line is the
    /// only trace of it that survives the purge.
    /// </para>
    /// <para>
    /// Read with the query filter ignored and the tenant matched explicitly, like everything else
    /// in this class. The ambient filter would usually agree, but the blast radius of a delete
    /// should not depend on who happens to hold the request context.
    /// </para>
    /// </remarks>
    private async Task CancelBillingAsync(Guid tenantId, CancellationToken ct)
    {
        var subscriptionId = await db.Subscriptions
            .IgnoreQueryFilters()
            .Where(s => s.TenantId == tenantId)
            .Select(s => s.StripeSubscriptionId)
            .FirstOrDefaultAsync(ct);

        if (string.IsNullOrWhiteSpace(subscriptionId)) return;

        try
        {
            await billing.CancelSubscriptionAsync(subscriptionId, ct);

            logger.LogWarning(
                "Cancelled Stripe subscription {SubscriptionId} for tenant {TenantId} ahead of "
                + "account deletion", subscriptionId, tenantId);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "Could not cancel Stripe subscription {SubscriptionId} for tenant {TenantId}. The "
                + "account is being deleted anyway — cancel this subscription by hand in the "
                + "Stripe dashboard, or the customer keeps being charged for an account that no "
                + "longer exists. This log line is the only record that survives the purge",
                subscriptionId, tenantId);
        }
    }
}

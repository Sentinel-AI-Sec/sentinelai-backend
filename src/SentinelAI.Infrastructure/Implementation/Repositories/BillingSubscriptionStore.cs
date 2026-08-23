using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

/// <summary>
/// The webhook's way to a subscription row. See <see cref="IBillingSubscriptionStore"/> for why
/// stepping around tenant isolation is necessary here and why it is safe.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is one of two places in the codebase that calls <c>IgnoreQueryFilters</c>, and the
/// smaller of them.</b> <c>TenantPurgeService</c> is the other; it ignores the filter and then
/// matches an explicit tenant id, so its blast radius is one tenant chosen by the caller. This
/// one cannot do that, because the caller is Stripe and Stripe does not know what a tenant is.
/// What bounds it instead is the key: a Stripe customer id, unique across the whole table, that
/// arrives only inside a payload whose HMAC has already been verified.
/// </para>
/// <para>
/// Kept to two methods for that reason. Every line here is a line a reviewer has to accept as
/// deliberately unisolated, so there is nothing in it that could have been done under the filter.
/// </para>
/// </remarks>
public sealed class BillingSubscriptionStore(SentinelDbContext db) : IBillingSubscriptionStore
{
    public async Task<Subscription?> FindByCustomerIdAsync(
        string stripeCustomerId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(stripeCustomerId)) return null;

        // Tracked, because the caller mutates what comes back and hands it to SaveAsync below.
        // A no-tracking read here would make every webhook a silent no-op.
        return await db.Subscriptions
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(s => s.StripeCustomerId == stripeCustomerId, ct);
    }

    public async Task SaveAsync(
        Subscription subscription, string planTier, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(subscription);

        subscription.UpdatedAt = DateTime.UtcNow;

        // Tenant is not ITenantOwned — it is the thing tenancy is defined against, so no query
        // filter applies to it and this is an ordinary read. Loaded rather than assumed present:
        // a subscription whose tenant has been deleted can still receive one late webhook, and
        // the entitlement write is skipped rather than throwing on a row that is gone.
        var tenant = await db.Tenants.FirstOrDefaultAsync(t => t.Id == subscription.TenantId, ct);

        if (tenant is not null) tenant.PlanTier = planTier;

        // One SaveChanges for both, so the subscription row and the entitlement it implies can
        // never be written apart. See IBillingSubscriptionStore.SaveAsync for what comes apart
        // if they are.
        await db.SaveChangesAsync(ct);
    }
}

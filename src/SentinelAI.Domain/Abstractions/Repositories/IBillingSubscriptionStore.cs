using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Abstractions.Repositories;

/// <summary>
/// Resolves a Stripe customer to the subscription it belongs to, across every tenant.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists because the webhook cannot be a tenant.</b> <c>SentinelDbContext</c> hangs
/// <c>e.TenantId == CurrentTenantId</c> on every <see cref="Abstractions.ITenantOwned"/> entity,
/// and <c>Subscription</c> is one — which is what stops any authenticated caller reading another
/// organisation's plan. Stripe authenticates with a signature over the payload, not a bearer
/// token, so <c>POST /v1/billing/webhook</c> runs with no tenant at all and the filter resolves
/// to <c>Guid.Empty</c>, matching nothing.
/// </para>
/// <para>
/// <b>The failure that produces is silent, which is why it gets its own type.</b> Query filters
/// do not affect writes, so a webhook handler working through the ordinary repository would read
/// back no subscription, decide there was nothing to update, and return <c>200 OK</c> to Stripe
/// — which would mark the delivery as successfully handled and never retry it. Customers would
/// pay, Stripe would show the subscription as active, and the product would keep every one of
/// them on the free tier with nothing anywhere reporting an error.
/// </para>
/// <para>
/// <b>Why not <c>AssumableCallerContext</c>.</b> That is the mechanism the scan worker uses for
/// the same problem, and it refuses on purpose inside an HTTP request: a request that could
/// assume a tenant would be a privilege escalation with the tenant id supplied by the thing being
/// escalated. A webhook is an HTTP request. So the bypass has to be narrow and explicit instead
/// — this interface, one implementation, two methods, keyed by a value only Stripe can produce.
/// </para>
/// <para>
/// <b>The tenant is still never chosen by the caller.</b> Nothing here takes a tenant id. The
/// only way in is a Stripe customer id, which arrives inside a payload whose HMAC has already
/// been verified against this deployment's webhook secret. Reaching another tenant's row through
/// this means forging that signature, which is the same thing as knowing the secret.
/// </para>
/// </remarks>
public interface IBillingSubscriptionStore
{
    /// <summary>
    /// The subscription holding this Stripe customer id, ignoring tenant isolation.
    /// </summary>
    /// <returns>
    /// Null when no tenant has ever started a checkout under this customer — a subscription
    /// created by hand in the Stripe dashboard, or an event for a customer belonging to a
    /// different deployment sharing the account. Both are refused rather than guessed at.
    /// </returns>
    Task<Subscription?> FindByCustomerIdAsync(string stripeCustomerId, CancellationToken ct = default);

    /// <summary>
    /// Saves changes to a subscription this store returned, and mirrors the entitlement onto the
    /// tenant that owns it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The two writes are one method because they must not come apart. <c>Tenant.PlanTier</c> is
    /// what the rest of the product reads to decide what an account may do; the subscription row
    /// is what the billing screen reads. Updating one without the other produces an account that
    /// is billed for Team and gated as free, or the reverse — and both are invisible until a
    /// customer complains, since each table is self-consistent on its own.
    /// </para>
    /// <para>
    /// The caller decides <paramref name="planTier"/>, because "what is this tenant entitled to"
    /// is a business rule about statuses and grace periods, not a storage concern. This
    /// guarantees only that the decision lands in both places or neither.
    /// </para>
    /// </remarks>
    /// <param name="subscription">A subscription previously returned by this store.</param>
    /// <param name="planTier">The entitlement to write onto the owning tenant.</param>
    Task SaveAsync(Subscription subscription, string planTier, CancellationToken ct = default);
}

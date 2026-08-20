using SentinelAI.Domain.Enums;

namespace SentinelAI.Application.Abstractions.Billing;

/// <summary>One sellable thing: a plan, a cadence, and the Stripe Price that bills it.</summary>
/// <param name="PlanId">
/// The plan id shared with the UI's <c>core/billing/plans.ts</c> — <c>developer</c>,
/// <c>team</c>, <c>enterprise</c>. Compared case-insensitively; stored as configured.
/// </param>
/// <param name="Period">Which cadence this price bills at.</param>
/// <param name="PriceId">The Stripe <c>price_...</c> id. Public, not a secret.</param>
public sealed record PlanPrice(string PlanId, BillingPeriod Period, string PriceId);

/// <summary>
/// Every price this deployment is willing to sell, and the only place a plan id becomes a
/// Stripe Price id.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is an allowlist before it is a lookup.</b> The browser asks to buy a plan by name;
/// it never sends a price id and could not be trusted with one if it did. A price id arriving
/// from a client is an input, not an instruction — without a server-side list, a caller who read
/// any <c>price_...</c> off a Stripe account (they are public identifiers, published in checkout
/// links) could check out against a one-cent price and be provisioned the Team plan by the
/// resulting webhook, because the webhook believes Stripe and Stripe was told what to charge by
/// the attacker. Resolving in this direction — name to price, against configuration — means the
/// set of things that can be bought is exactly the set an operator wrote down.
/// </para>
/// <para>
/// <see cref="FindByPriceId"/> is the same table read backwards, and it is what makes the
/// webhook honest. Stripe reports the Price that was actually billed; mapping that back to a
/// plan id is how the tenant's entitlement comes from what Stripe charged rather than from what
/// the checkout request asked for. An unrecognised price resolves to no plan and is refused
/// loudly rather than quietly granting the last thing that was asked for.
/// </para>
/// <para>
/// Built from configuration by <c>BillingSettingsLoader</c> (Infrastructure, which owns
/// configuration) and registered as a singleton — the same split <c>EgressPolicy</c> uses.
/// </para>
/// </remarks>
public sealed class PlanCatalog
{
    private readonly IReadOnlyList<PlanPrice> _prices;

    public PlanCatalog(IEnumerable<PlanPrice> prices)
    {
        ArgumentNullException.ThrowIfNull(prices);

        _prices = [.. prices
            .Where(p => !string.IsNullOrWhiteSpace(p.PlanId) && !string.IsNullOrWhiteSpace(p.PriceId))
            .Select(p => new PlanPrice(p.PlanId.Trim(), p.Period, p.PriceId.Trim()))];
    }

    /// <summary>Every configured price. Empty on a deployment that sells nothing.</summary>
    public IReadOnlyList<PlanPrice> Prices => _prices;

    /// <summary>
    /// Whether anything can be bought at all. False is a legitimate state — a self-hosted or
    /// demo deployment — and the billing endpoints say so rather than failing at Stripe.
    /// </summary>
    public bool IsConfigured => _prices.Count > 0;

    /// <summary>The price for a plan and cadence, or null if this deployment does not sell it.</summary>
    public PlanPrice? Find(string? planId, BillingPeriod period) =>
        string.IsNullOrWhiteSpace(planId)
            ? null
            : _prices.FirstOrDefault(p =>
                p.Period == period
                && string.Equals(p.PlanId, planId.Trim(), StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// What a Stripe Price id was sold as, or null if this deployment never offered it.
    /// </summary>
    /// <remarks>
    /// Null is a real answer and the caller must handle it: it is what happens when a price is
    /// retired from configuration while a customer is still subscribed to it, or when a
    /// subscription was created by hand in the Stripe dashboard. Guessing a plan for it would
    /// grant an entitlement nobody configured.
    /// </remarks>
    public PlanPrice? FindByPriceId(string? priceId) =>
        string.IsNullOrWhiteSpace(priceId)
            ? null
            : _prices.FirstOrDefault(p =>
                string.Equals(p.PriceId, priceId.Trim(), StringComparison.Ordinal));
}

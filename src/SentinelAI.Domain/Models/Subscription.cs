using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;

namespace SentinelAI.Domain.Models;

/// <summary>
/// What one tenant is paying for. At most one row per tenant.
/// </summary>
/// <remarks>
/// <para>
/// <b>The tenant is the customer, not the user.</b> Every other paid thing in this system is
/// scoped to a tenant — projects, scans, retention — and <see cref="Tenant.PlanTier"/> is
/// already the field the rest of the product reads to decide what an account may do. Billing a
/// <see cref="User"/> instead would mean an organisation's entitlement depended on which of its
/// members happened to have paid, and would silently revoke the plan the day that person's
/// account was deleted.
/// </para>
/// <para>
/// <b>This row is a cache of Stripe's answer, never the source of truth.</b> Stripe decides
/// whether a card was charged; this table records what Stripe last told us through a signed
/// webhook so the product can answer "what plan is this tenant on" without a network call on
/// every request. Nothing outside <c>HandleBillingWebhookCommandHandler</c> may write
/// <see cref="Status"/>, <see cref="CurrentPeriodEnd"/> or <see cref="PlanId"/> — a redirect
/// back from Checkout is not proof of payment, and neither is a request body.
/// </para>
/// <para>
/// It implements <see cref="ITenantOwned"/>, so <c>SentinelDbContext</c> filters it to the
/// caller's tenant automatically and no billing query can read another organisation's plan. The
/// webhook is the one caller that cannot work under that filter — Stripe authenticates a
/// signature, not a tenant — and it goes through <c>IStripeSubscriptionStore</c>, which is the
/// single reviewable place that steps around it.
/// </para>
/// </remarks>
public class Subscription : ITenantOwned
{
    public Guid Id { get; set; }

    public Guid TenantId { get; set; }

    /// <summary>
    /// The plan the tenant is on: <c>developer</c>, <c>team</c>, <c>enterprise</c>.
    /// </summary>
    /// <remarks>
    /// A string keyed against <c>PlanCatalog</c> rather than an enum, and that is a decision
    /// about migrations. Plans are a commercial artefact — they get renamed, split and retired
    /// on a marketing timescale — and the UI already carries the same ids in
    /// <c>core/billing/plans.ts</c>. As an enum, adding a tier would mean a schema migration to
    /// sell something; as a string checked against configuration, it is a price id and a line of
    /// copy. Empty means no paid plan has ever been bought.
    /// </remarks>
    public string PlanId { get; set; } = string.Empty;

    /// <summary>Null until something is bought — the free tier has no cadence.</summary>
    public BillingPeriod? Period { get; set; }

    public SubscriptionStatus Status { get; set; } = SubscriptionStatus.None;

    /// <summary>Seats. One unless the plan is sold per seat and more than one was bought.</summary>
    public int Quantity { get; set; } = 1;

    /// <summary>
    /// Stripe's customer id. Created on the first checkout attempt and kept forever after.
    /// </summary>
    /// <remarks>
    /// Written before the tenant has paid for anything — <c>CreateCheckoutSessionCommandHandler</c>
    /// persists it as soon as Stripe mints the customer, so a visitor who abandons the payment
    /// page and comes back does not accumulate a second Stripe customer per attempt. A row
    /// carrying a customer id and <see cref="SubscriptionStatus.None"/> is therefore normal and
    /// means exactly "started checkout at least once, never completed one".
    /// </remarks>
    public string? StripeCustomerId { get; set; }

    public string? StripeSubscriptionId { get; set; }

    /// <summary>The Price object actually being billed. What <see cref="PlanId"/> was resolved from.</summary>
    public string? StripePriceId { get; set; }

    /// <summary>When the paid period ends — the renewal date, or the cut-off when winding down.</summary>
    public DateTime? CurrentPeriodEnd { get; set; }

    /// <summary>Null unless <see cref="Status"/> is <see cref="SubscriptionStatus.Trialing"/>.</summary>
    public DateTime? TrialEnd { get; set; }

    /// <summary>Cancelled, but paid up to <see cref="CurrentPeriodEnd"/> and entitled until then.</summary>
    public bool CancelAtPeriodEnd { get; set; }

    /// <summary>
    /// The <c>created</c> timestamp of the most recent Stripe event applied to this row.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Stripe delivers at least once and does not guarantee order. Every subscription event
    /// carries the <em>whole</em> current state of the subscription rather than a delta, so a
    /// redelivered or overtaken event does not merely repeat work — it rewrites this row with a
    /// state that has since been superseded. The observable failure is a customer who upgraded
    /// and then, minutes later, appears to be back on the old plan, with the correct answer
    /// visible in Stripe the whole time.
    /// </para>
    /// <para>
    /// Comparing against this makes applying an event idempotent and monotonic in one check.
    /// Null means no state-bearing event has landed yet.
    /// </para>
    /// </remarks>
    public DateTime? LastEventAt { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime UpdatedAt { get; set; }

    public Tenant? Tenant { get; set; }
}

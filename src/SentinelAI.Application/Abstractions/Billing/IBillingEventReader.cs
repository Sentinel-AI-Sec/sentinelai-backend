using SentinelAI.Domain.Enums;

namespace SentinelAI.Application.Abstractions.Billing;

/// <summary>
/// Verifies a webhook's signature and translates it into something this codebase understands.
/// </summary>
/// <remarks>
/// <para>
/// <b>The signature check is the authentication for this endpoint.</b> <c>POST
/// /v1/billing/webhook</c> is the only unauthenticated write in the API: it carries no bearer
/// token, because Stripe has none to send. What stands in for one is an HMAC over the exact
/// bytes of the request body, keyed with a secret only Stripe and this deployment know. Without
/// it, anyone who can reach the URL can post a <c>checkout.session.completed</c> for any
/// customer id and promote that account to any plan, for free — the webhook is the one thing in
/// the system permitted to grant a paid entitlement.
/// </para>
/// <para>
/// <b>Which is why this takes the raw body as a string and not a parsed model.</b> The HMAC is
/// over the bytes as sent. Letting ASP.NET Core bind the body to a type first and re-serializing
/// it would change whitespace, key order and number formatting, and every signature would fail
/// — or worse, would be made to pass by skipping the check.
/// </para>
/// </remarks>
public interface IBillingEventReader
{
    /// <summary>
    /// Reads one webhook delivery.
    /// </summary>
    /// <param name="payload">The request body, exactly as received.</param>
    /// <param name="signatureHeader">The <c>Stripe-Signature</c> header.</param>
    /// <returns>
    /// The event, or <see langword="null"/> when the delivery is genuine but of a type this
    /// product does not act on. Null is an ordinary outcome, not a failure: Stripe sends dozens
    /// of event types and the endpoint must answer <c>200</c> to all of them, or Stripe retries
    /// them for days and eventually disables the endpoint — taking the events that <em>do</em>
    /// matter down with it.
    /// </returns>
    /// <exception cref="BillingSignatureException">
    /// The signature is absent, malformed, or does not verify. Distinct from null precisely
    /// because the answers differ: this one is a <c>400</c>, and a retry will not help.
    /// </exception>
    BillingEvent? Read(string payload, string? signatureHeader);
}

/// <summary>A webhook delivery worth acting on, with Stripe's vocabulary already translated.</summary>
public sealed record BillingEvent
{
    /// <summary>Stripe's event id. Logged, so a delivery can be found in the Stripe dashboard.</summary>
    public required string EventId { get; init; }

    /// <summary>
    /// When Stripe created the event — not when we received it.
    /// </summary>
    /// <remarks>
    /// The ordering key. Retries and redeliveries arrive with the original timestamp, so
    /// comparing this against <c>Subscription.LastEventAt</c> makes applying an event both
    /// idempotent and monotonic. Using receipt time instead would make every redelivery look
    /// newer than the state it was already overwritten by.
    /// </remarks>
    public required DateTime OccurredAt { get; init; }

    public required BillingEventKind Kind { get; init; }

    /// <summary>
    /// Stripe's customer id — how a delivery is resolved to a tenant.
    /// </summary>
    /// <remarks>
    /// Every event kind handled here carries one, which is why the customer id and not session
    /// metadata is the join. Metadata is set by whoever created the object; the customer is set
    /// by Stripe on every subscription and invoice belonging to it, including ones created from
    /// the dashboard by a human rather than through our checkout.
    /// </remarks>
    public required string CustomerId { get; init; }

    public string? SubscriptionId { get; init; }

    /// <summary>The Price actually billed. Resolved back to a plan through <see cref="PlanCatalog"/>.</summary>
    public string? PriceId { get; init; }

    public SubscriptionStatus Status { get; init; } = SubscriptionStatus.None;

    /// <summary>Seats. Stripe's line quantity, defaulting to one.</summary>
    public int Quantity { get; init; } = 1;

    public DateTime? CurrentPeriodEnd { get; init; }

    public DateTime? TrialEnd { get; init; }

    public bool CancelAtPeriodEnd { get; init; }
}

/// <summary>The kinds of delivery this product acts on. Everything else is read as null.</summary>
public enum BillingEventKind
{
    /// <summary>
    /// <c>checkout.session.completed</c> — the customer finished paying.
    /// </summary>
    /// <remarks>
    /// Carries the subscription id and little else worth trusting about state; the
    /// <c>customer.subscription.*</c> event that accompanies it is what says which plan, at what
    /// status, until when. Handled separately for that reason rather than being folded in.
    /// </remarks>
    CheckoutCompleted,

    /// <summary>
    /// <c>customer.subscription.created | updated | deleted</c> — the whole current state.
    /// </summary>
    /// <remarks>
    /// One kind for all three because Stripe sends the complete subscription object every time,
    /// with <c>status</c> already saying which happened — a deletion arrives as the same object
    /// with <c>status: canceled</c>. Branching on the verb as well as the status would give two
    /// sources for one answer, and they would eventually disagree.
    /// </remarks>
    SubscriptionChanged,

    /// <summary>
    /// <c>invoice.payment_failed</c> — a renewal did not go through.
    /// </summary>
    /// <remarks>
    /// Acted on so the billing screen can say "payment failed" while Stripe is still retrying,
    /// which is the window in which a customer can actually fix it. The subscription's own
    /// status catches up shortly afterwards through <see cref="SubscriptionChanged"/>.
    /// </remarks>
    PaymentFailed
}

/// <summary>
/// A webhook delivery whose signature did not verify.
/// </summary>
/// <remarks>
/// Answered with <c>400</c> and no detail. Either the deployment's webhook secret is wrong — in
/// which case Stripe's own dashboard shows the failures and is the right place to debug it — or
/// somebody is posting forged events at the endpoint, and a helpful error message would tell
/// them which part they got wrong.
/// </remarks>
public sealed class BillingSignatureException(string message, Exception? inner = null)
    : Exception(message, inner);

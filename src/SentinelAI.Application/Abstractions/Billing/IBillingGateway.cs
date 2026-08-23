namespace SentinelAI.Application.Abstractions.Billing;

/// <summary>
/// Everything this product asks the payment processor to do.
/// </summary>
/// <remarks>
/// <para>
/// <b>Four calls, and none of them touches a card.</b> The browser is redirected to a
/// Stripe-hosted page and comes back; no card number, payment method id or publishable key ever
/// enters this origin or this codebase. That is what keeps the whole application out of PCI
/// scope, and it is why there is no "charge" method here to be tempted by.
/// </para>
/// <para>
/// <b>Deliberately vendor-neutral.</b> Stripe's SDK types stop at the Infrastructure boundary,
/// exactly as the model providers and the vector store do — the handlers above deal in ids and
/// URLs. The practical payoff is not portability, which nobody is planning; it is that the
/// checkout, portal and webhook handlers are testable with a fake, so the rules that matter (the
/// price allowlist, the return-origin check, out-of-order webhooks) are pinned by tests that do
/// not need a Stripe account or a network.
/// </para>
/// </remarks>
public interface IBillingGateway
{
    /// <summary>
    /// The tenant's Stripe customer, creating one on first use.
    /// </summary>
    /// <remarks>
    /// <paramref name="existingCustomerId"/> is passed rather than looked up here so this stays
    /// a pure translation of one Stripe call — the caller owns the row that remembers it. Reusing
    /// the id matters: a new customer per checkout attempt would scatter one organisation's
    /// invoices across several Stripe customers, and the billing portal would only ever show
    /// whichever one it was last handed.
    /// </remarks>
    /// <returns>The Stripe customer id.</returns>
    Task<string> GetOrCreateCustomerAsync(
        Guid tenantId, string email, string? existingCustomerId, CancellationToken ct = default);

    /// <summary>Starts a hosted Checkout Session.</summary>
    /// <returns>The Stripe-hosted URL to send the browser to.</returns>
    Task<string> CreateCheckoutSessionAsync(CheckoutSessionRequest request, CancellationToken ct = default);

    /// <summary>Opens Stripe's billing portal, where a customer changes card, or cancels.</summary>
    /// <returns>The Stripe-hosted URL to send the browser to.</returns>
    Task<string> CreatePortalSessionAsync(string customerId, string returnUrl, CancellationToken ct = default);

    /// <summary>
    /// Ends a subscription immediately. Called when the account itself is being deleted.
    /// </summary>
    /// <remarks>
    /// Immediate rather than at period end, which is the opposite of what the cancel button in
    /// the portal does — and correct here for a reason that is not about billing policy: after
    /// account deletion there is no row left to receive the webhook, no tenant to re-provision,
    /// and nothing on our side that would ever notice the subscription again. Leaving it to lapse
    /// would keep charging a customer for an account that no longer exists, with no screen
    /// anywhere in this product able to show it to them.
    /// </remarks>
    Task CancelSubscriptionAsync(string subscriptionId, CancellationToken ct = default);
}

/// <summary>What to put in a Checkout Session.</summary>
public sealed record CheckoutSessionRequest
{
    public required string CustomerId { get; init; }

    /// <summary>
    /// Resolved from the plan the caller named, through <see cref="PlanCatalog"/> — never taken
    /// from the request body. See that type for why the direction matters.
    /// </summary>
    public required string PriceId { get; init; }

    public required int Quantity { get; init; }

    /// <summary>Checked against <see cref="BillingSettings.IsAllowedReturnUrl"/> before it gets here.</summary>
    public required string SuccessUrl { get; init; }

    /// <summary>Checked against <see cref="BillingSettings.IsAllowedReturnUrl"/> before it gets here.</summary>
    public required string CancelUrl { get; init; }

    /// <summary>
    /// Recorded on the Stripe customer and session as metadata.
    /// </summary>
    /// <remarks>
    /// Not how the webhook finds the tenant — that goes through the customer id, which Stripe
    /// puts on every subscription event whether or not anybody set metadata. This is here so a
    /// person looking at a payment in the Stripe dashboard can tell which account it belongs to,
    /// which is the question every billing support ticket starts with.
    /// </remarks>
    public required Guid TenantId { get; init; }
}

/// <summary>
/// The payment processor refused or could not be reached.
/// </summary>
/// <remarks>
/// A distinct exception so the handlers can answer <c>502 Bad Gateway</c> — "the vendor said no"
/// — rather than letting a Stripe SDK type reach a <c>catch</c> in Application, and rather than
/// reporting a vendor outage as a fault in this API. The message is safe to log; it is Stripe's
/// error text, which never contains card data.
/// </remarks>
public sealed class BillingGatewayException(string message, Exception? inner = null)
    : Exception(message, inner);

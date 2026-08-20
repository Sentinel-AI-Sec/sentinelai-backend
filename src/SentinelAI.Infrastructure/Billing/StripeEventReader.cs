using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Enums;
using Stripe;
using StripeSubscription = Stripe.Subscription;

namespace SentinelAI.Infrastructure.Billing;

/// <summary>
/// Verifies a Stripe webhook signature and translates the payload into a <see cref="BillingEvent"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>This class is the authentication for the one unauthenticated write in the API.</b> Nothing
/// else stands between a POST to <c>/v1/billing/webhook</c> and a tenant being granted a paid
/// plan. <see cref="EventUtility.ConstructEvent(string, string, string)"/> recomputes the HMAC
/// over the exact bytes received, compares it in constant time, and rejects a timestamp outside
/// its tolerance — which is what stops a replay of a delivery captured off the wire. It throws
/// on any failure, and this class turns every one of those into
/// <see cref="BillingSignatureException"/> without adding a fallback path. There is no
/// configuration that skips it.
/// </para>
/// <para>
/// <b>Unhandled event types return null, not an error.</b> A Stripe endpoint receives whatever
/// event types it is subscribed to, and an account's settings can be changed by someone who is
/// not reading this code. Answering anything other than <c>2xx</c> to an event we simply do not
/// care about makes Stripe retry it for days and eventually disable the endpoint — which would
/// take down the events that do matter along with it.
/// </para>
/// </remarks>
public sealed class StripeEventReader(IOptions<StripeOptions> options) : IBillingEventReader
{
    private readonly string _webhookSecret = options.Value.WebhookSecret;

    public BillingEvent? Read(string payload, string? signatureHeader)
    {
        if (string.IsNullOrWhiteSpace(_webhookSecret))
        {
            // Refused rather than waved through. An endpoint that accepts unverified events on a
            // deployment which forgot to configure the secret is an endpoint anyone can use to
            // grant themselves any plan — and it would look like it was working.
            throw new BillingSignatureException(
                $"No webhook secret is configured ({StripeOptions.SectionName}:WebhookSecret is "
                + "empty), so no delivery can be verified and none will be accepted.");
        }

        if (string.IsNullOrWhiteSpace(signatureHeader))
            throw new BillingSignatureException("The Stripe-Signature header is missing.");

        Event stripeEvent;

        try
        {
            stripeEvent = EventUtility.ConstructEvent(
                payload,
                signatureHeader,
                _webhookSecret,

                // Tolerance in seconds. Stripe's default, and the part of the check that rejects
                // a delivery captured off the wire and replayed later — the signature over an
                // old payload stays valid forever, so recency has to be asserted separately.
                tolerance: 300,

                // The one relaxation, and it is not a security one.
                //
                // Left at its default, this throws when the event's api_version differs from the
                // version Stripe.net was compiled against. That comparison has nothing to do with
                // authenticity: the HMAC has already been verified by the time it runs. What it
                // guards against is a field this SDK would deserialize differently — and the
                // fields read below (customer, status, items[].price.id, current_period_end) have
                // been stable across many versions.
                //
                // The cost of leaving it on is severe and arrives without warning. A Stripe
                // account's default API version is set on the account, not by us, and it moves
                // when Stripe upgrades it or when somebody clicks upgrade in the dashboard.
                // The moment it drifts from whatever version this build of Stripe.net pins, every
                // delivery starts throwing — which this class reports as a signature failure, so
                // the endpoint answers 400 to genuine events, Stripe retries them for three days
                // and then disables the endpoint. Customers pay, and nobody is provisioned.
                // Upgrading the NuGet package would then be a change that silently repairs
                // billing, which is not a thing anyone should have to discover.
                throwOnApiVersionMismatch: false);
        }
        catch (StripeException ex)
        {
            throw new BillingSignatureException("The webhook signature did not verify.", ex);
        }

        return stripeEvent.Type switch
        {
            "checkout.session.completed" => FromCheckoutSession(stripeEvent),

            // All three, because Stripe sends the whole subscription object every time and its
            // own status field already says which happened — a deletion arrives as the same
            // object with status "canceled". Branching on the verb as well would give two sources
            // for one answer, and they would eventually disagree.
            "customer.subscription.created"
                or "customer.subscription.updated"
                or "customer.subscription.deleted" => FromSubscription(stripeEvent),

            "invoice.payment_failed" => FromInvoice(stripeEvent),

            _ => null,
        };
    }

    /// <summary>
    /// The checkout finished. Carries the subscription id and the customer, and little else worth
    /// trusting about state — the accompanying <c>customer.subscription.*</c> event says the rest.
    /// </summary>
    private static BillingEvent? FromCheckoutSession(Event stripeEvent)
    {
        if (stripeEvent.Data.Object is not Stripe.Checkout.Session session) return null;

        // A one-off payment session has no subscription, and nothing in this product sells one.
        // Reading it as a subscription event would set a plan that never renews.
        if (string.IsNullOrWhiteSpace(session.CustomerId)) return null;

        return new BillingEvent
        {
            EventId = stripeEvent.Id,
            OccurredAt = stripeEvent.Created,
            Kind = BillingEventKind.CheckoutCompleted,
            CustomerId = session.CustomerId,
            SubscriptionId = session.SubscriptionId,
        };
    }

    /// <summary>The subscription's complete current state, as Stripe now holds it.</summary>
    private static BillingEvent? FromSubscription(Event stripeEvent)
    {
        if (stripeEvent.Data.Object is not StripeSubscription subscription) return null;
        if (string.IsNullOrWhiteSpace(subscription.CustomerId)) return null;

        // The first item is the subscription. Nothing here sells add-ons or metered lines, so a
        // second item would mean somebody built a subscription by hand in the dashboard — in
        // which case the first is still the closest thing to an answer, and PlanCatalog refuses
        // the price if it is not one this deployment sells.
        var item = subscription.Items?.Data?.FirstOrDefault();

        return new BillingEvent
        {
            EventId = stripeEvent.Id,
            OccurredAt = stripeEvent.Created,
            Kind = BillingEventKind.SubscriptionChanged,
            CustomerId = subscription.CustomerId,
            SubscriptionId = subscription.Id,
            PriceId = item?.Price?.Id,
            Status = MapStatus(subscription.Status),
            Quantity = item?.Quantity is > 0 and var quantity ? (int)quantity! : 1,

            // Per-item since Stripe moved the period off the subscription: a subscription can in
            // principle bill its lines on different cycles, so the dates live where the price
            // does. Reading the (now absent) subscription-level field is the upgrade mistake that
            // leaves every renewal date silently null.
            CurrentPeriodEnd = item?.CurrentPeriodEnd,

            TrialEnd = subscription.TrialEnd,
            CancelAtPeriodEnd = subscription.CancelAtPeriodEnd,
        };
    }

    /// <summary>
    /// A renewal did not go through. Acted on so the billing screen can say so while Stripe is
    /// still retrying — which is the window in which a customer can actually fix it.
    /// </summary>
    private static BillingEvent? FromInvoice(Event stripeEvent)
    {
        if (stripeEvent.Data.Object is not Invoice invoice) return null;
        if (string.IsNullOrWhiteSpace(invoice.CustomerId)) return null;

        return new BillingEvent
        {
            EventId = stripeEvent.Id,
            OccurredAt = stripeEvent.Created,
            Kind = BillingEventKind.PaymentFailed,
            CustomerId = invoice.CustomerId,
            Status = SubscriptionStatus.PastDue,
        };
    }

    /// <summary>
    /// Stripe's status vocabulary, narrowed to the six states this product distinguishes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two of Stripe's statuses are folded rather than dropped. <c>unpaid</c> means Stripe has
    /// stopped retrying where <c>past_due</c> means it is still trying; both mean the card did
    /// not work, and the customer's next action is identical. <c>incomplete_expired</c> is a
    /// subscription whose first payment never succeeded, which for entitlement purposes is a
    /// subscription that ended. The distinctions are preserved in the Stripe dashboard, which is
    /// where a billing operator looks; inventing enum members we would render identically would
    /// put words on a screen that nothing branches on.
    /// </para>
    /// <para>
    /// An unrecognised status maps to <see cref="SubscriptionStatus.Incomplete"/> — the one
    /// member that grants nothing and reads as "not settled yet". Defaulting to
    /// <see cref="SubscriptionStatus.Active"/> would mean any future Stripe status this code has
    /// never seen silently hands out a paid plan.
    /// </para>
    /// </remarks>
    private static SubscriptionStatus MapStatus(string? status) => status switch
    {
        "active" => SubscriptionStatus.Active,
        "trialing" => SubscriptionStatus.Trialing,
        "past_due" or "unpaid" => SubscriptionStatus.PastDue,
        "canceled" or "incomplete_expired" => SubscriptionStatus.Canceled,
        "incomplete" or "paused" => SubscriptionStatus.Incomplete,
        _ => SubscriptionStatus.Incomplete,
    };
}

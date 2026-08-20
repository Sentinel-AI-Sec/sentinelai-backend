using System.Net;
using MediatR;
using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Premitives;
using SubscriptionEntity = SentinelAI.Domain.Models.Subscription;

namespace SentinelAI.Application.Features.Billing.Commands.HandleWebhook;

/// <summary>
/// Verifies a Stripe delivery and writes what it says onto the tenant's subscription.
/// </summary>
/// <remarks>
/// <para>
/// <b>Almost everything here answers <c>200</c>, including most of the failures.</b> Stripe reads
/// a non-2xx as "try again", retries with backoff for up to three days, and disables an endpoint
/// that keeps failing — which would take down the deliveries that matter along with the one that
/// did not. So an event for a customer nobody recognises, an event of a type this product ignores
/// and an event that has already been applied are all logged and acknowledged. The single
/// exception is a signature that does not verify: retrying will not fix a forged or misconfigured
/// delivery, and answering <c>200</c> to it would hide a wrong webhook secret behind a green
/// dashboard.
/// </para>
/// <para>
/// <b>The plan comes from the price Stripe billed, never from what the checkout asked for.</b>
/// <c>PlanCatalog.FindByPriceId</c> resolves it in that direction on purpose — see that type. An
/// unrecognised price leaves the plan alone rather than guessing at one.
/// </para>
/// </remarks>
public sealed class HandleBillingWebhookCommandHandler(
    IBillingEventReader reader,
    IBillingSubscriptionStore store,
    BillingSettings settings,
    ILogger<HandleBillingWebhookCommandHandler> logger)
    : IRequestHandler<HandleBillingWebhookCommand, Response>
{
    public async Task<Response> Handle(HandleBillingWebhookCommand request, CancellationToken ct)
    {
        BillingEvent? billingEvent;

        try
        {
            billingEvent = reader.Read(request.Payload, request.SignatureHeader);
        }
        catch (BillingSignatureException ex)
        {
            // Logged with no detail from the payload. Either this deployment's webhook secret is
            // wrong — in which case Stripe's own dashboard lists the failures and is the place to
            // fix it — or somebody is posting forged events, and an error message naming the part
            // they got wrong is a hint they did not have before.
            logger.LogWarning(ex, "Rejected a billing webhook whose signature did not verify");

            return await Response.FailureAsync(
                "signature verification failed", HttpStatusCode.BadRequest);
        }

        if (billingEvent is null)
        {
            // A genuine delivery of a type this product does not act on. Acknowledged silently:
            // Stripe sends dozens of event types and logging each one would bury the ones that
            // matter.
            return await Response.SuccessAsync(null, "event ignored", HttpStatusCode.OK);
        }

        var subscription = await store.FindByCustomerIdAsync(billingEvent.CustomerId, ct);

        if (subscription is null)
        {
            // No tenant has ever started a checkout under this customer. A subscription created
            // by hand in the Stripe dashboard, or an event belonging to another deployment
            // sharing the Stripe account. Acknowledged so Stripe stops retrying, and logged at
            // warning because a payment nobody can attribute is worth a human's attention.
            logger.LogWarning(
                "Billing webhook {EventId} ({Kind}) names Stripe customer {CustomerId}, which no "
                + "tenant has a subscription row for. Nothing was changed",
                billingEvent.EventId, billingEvent.Kind, billingEvent.CustomerId);

            return await Response.SuccessAsync(null, "unknown customer", HttpStatusCode.OK);
        }

        var applied = billingEvent.Kind switch
        {
            BillingEventKind.CheckoutCompleted => ApplyCheckoutCompleted(subscription, billingEvent),
            BillingEventKind.SubscriptionChanged => ApplySubscriptionChanged(subscription, billingEvent),
            BillingEventKind.PaymentFailed => ApplyPaymentFailed(subscription, billingEvent),
            _ => false,
        };

        if (!applied)
            return await Response.SuccessAsync(null, "event superseded", HttpStatusCode.OK);

        var tier = BillingEntitlement.TierFor(subscription, settings);

        await store.SaveAsync(subscription, tier, ct);

        logger.LogInformation(
            "Billing webhook {EventId} ({Kind}) applied to tenant {TenantId}: plan {PlanId}, "
            + "status {Status}, entitlement {Tier}",
            billingEvent.EventId, billingEvent.Kind, subscription.TenantId,
            subscription.PlanId, subscription.Status, tier);

        return await Response.SuccessAsync(null, "event applied", HttpStatusCode.OK);
    }

    /// <summary>
    /// Links the Stripe subscription to the tenant, and nothing else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A checkout session says a payment happened; the <c>customer.subscription.*</c> event that
    /// accompanies it says which plan, at what status, until when. Setting a status here from the
    /// weaker signal would mean two events writing the same fields with different confidence, and
    /// whichever landed second would win.
    /// </para>
    /// <para>
    /// <c>LastEventAt</c> is deliberately not advanced. This event carries no state to be
    /// superseded, and stamping the ordering clock from it would let a checkout that Stripe
    /// happened to deliver late suppress the subscription event that actually grants the plan.
    /// </para>
    /// </remarks>
    private static bool ApplyCheckoutCompleted(SubscriptionEntity subscription, BillingEvent evt)
    {
        if (string.IsNullOrWhiteSpace(evt.SubscriptionId)) return false;
        if (subscription.StripeSubscriptionId == evt.SubscriptionId) return false;

        subscription.StripeSubscriptionId = evt.SubscriptionId;
        return true;
    }

    /// <summary>
    /// Writes the whole current state Stripe reported, if it is newer than what we already have.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <see cref="SubscriptionEntity.LastEventAt"/> comparison is what makes redelivery a
    /// no-op and an overtaken event harmless. Stripe delivers at least once and does not
    /// guarantee order, and each of these events carries the complete subscription rather than a
    /// delta — so without the check, a redelivered upgrade-then-downgrade pair applied in the
    /// wrong order leaves a customer on the plan they left, with Stripe showing the right one the
    /// whole time. <c>&lt;</c> rather than <c>&lt;=</c>: two events can share a timestamp, and
    /// re-applying an identical state costs nothing.
    /// </para>
    /// <para>
    /// An unrecognised price leaves <see cref="SubscriptionEntity.PlanId"/> untouched rather than
    /// clearing it. It means a price was retired from configuration while somebody was still
    /// subscribed to it; keeping the plan they are paying for is right, and the status they are
    /// in still updates.
    /// </para>
    /// </remarks>
    private bool ApplySubscriptionChanged(SubscriptionEntity subscription, BillingEvent evt)
    {
        if (subscription.LastEventAt is { } last && evt.OccurredAt < last) return false;

        subscription.StripeSubscriptionId = evt.SubscriptionId ?? subscription.StripeSubscriptionId;
        subscription.StripePriceId = evt.PriceId ?? subscription.StripePriceId;
        subscription.Status = evt.Status;
        subscription.Quantity = evt.Quantity;
        subscription.CurrentPeriodEnd = evt.CurrentPeriodEnd;
        subscription.TrialEnd = evt.TrialEnd;
        subscription.CancelAtPeriodEnd = evt.CancelAtPeriodEnd;
        subscription.LastEventAt = evt.OccurredAt;

        if (settings.Plans.FindByPriceId(evt.PriceId) is { } price)
        {
            subscription.PlanId = price.PlanId;
            subscription.Period = price.Period;
        }
        else if (!string.IsNullOrWhiteSpace(evt.PriceId))
        {
            logger.LogWarning(
                "Billing webhook {EventId} reports Stripe price {PriceId} for tenant {TenantId}, "
                + "which is not in this deployment's Billing:Prices. The plan was left as "
                + "{PlanId} and only the status was updated",
                evt.EventId, evt.PriceId, subscription.TenantId, subscription.PlanId);
        }

        return true;
    }

    /// <summary>
    /// Marks the subscription past due so the billing screen can say so while Stripe retries.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only ever moves an entitled subscription to <see cref="SubscriptionStatus.PastDue"/>.
    /// A failed invoice on a subscription that is already cancelled or incomplete says nothing
    /// new, and promoting one of those into <c>past_due</c> would read on the screen as an active
    /// plan with a payment problem — which is a better state than the one it is actually in.
    /// </para>
    /// <para>
    /// The entitlement itself survives: <see cref="BillingEntitlement"/> keeps the plan through
    /// <c>past_due</c> on purpose, so a customer whose card expired is told about it rather than
    /// locked out during the window in which they can fix it.
    /// </para>
    /// </remarks>
    private static bool ApplyPaymentFailed(SubscriptionEntity subscription, BillingEvent evt)
    {
        if (subscription.LastEventAt is { } last && evt.OccurredAt < last) return false;

        if (subscription.Status is not (SubscriptionStatus.Active or SubscriptionStatus.Trialing))
            return false;

        subscription.Status = SubscriptionStatus.PastDue;
        subscription.LastEventAt = evt.OccurredAt;
        return true;
    }
}

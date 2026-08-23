using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Enums;
using SubscriptionEntity = SentinelAI.Domain.Models.Subscription;

namespace SentinelAI.Application.Features.Billing;

/// <summary>
/// Turns a subscription's state into the one string the rest of the product gates on.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the whole reason <c>Tenant.PlanTier</c> keeps existing.</b> Feature gates ask
/// "what is this account entitled to", not "what did Stripe's most recent webhook say about an
/// invoice". Answering that question in one pure function, called from one place, is what keeps
/// Stripe's status vocabulary from spreading through the codebase — the day a quota check has to
/// understand the difference between <c>past_due</c> and <c>unpaid</c> is the day entitlement
/// starts disagreeing with itself.
/// </para>
/// <para>
/// Pure and static because it is a rule, not a service: it reads a row and returns a string, so
/// the grace-period decision below is pinned by a test that constructs a subscription and
/// nothing else.
/// </para>
/// </remarks>
public static class BillingEntitlement
{
    /// <summary>
    /// The plan tier this subscription entitles its tenant to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><see cref="SubscriptionStatus.PastDue"/> keeps the paid plan, and that is deliberate.</b>
    /// It is not a lapsed account — it is a card that failed once while Stripe is still retrying,
    /// which is the window in which a customer can fix it. Downgrading immediately would lock a
    /// paying customer out of a security product over an expired card, hours before the
    /// replacement charge succeeds. Stripe ends the retry cycle on its own schedule and sends
    /// <c>canceled</c>; that is the event that removes the entitlement, and it is the one a
    /// customer has already been emailed about.
    /// </para>
    /// <para>
    /// <see cref="SubscriptionStatus.Trialing"/> is entitled, because a trial that grants nothing
    /// is not a trial. <see cref="SubscriptionStatus.Incomplete"/> is not: the first payment has
    /// never succeeded, so nothing has been established to give the benefit of the doubt to.
    /// </para>
    /// <para>
    /// <c>CancelAtPeriodEnd</c> is not consulted. A customer who cancels has paid through
    /// <c>CurrentPeriodEnd</c> and stays entitled until Stripe actually ends the subscription —
    /// which arrives as its own event. Acting on the flag early would charge for a period and
    /// then withhold it.
    /// </para>
    /// </remarks>
    public static string TierFor(SubscriptionEntity subscription, BillingSettings settings)
    {
        ArgumentNullException.ThrowIfNull(subscription);
        ArgumentNullException.ThrowIfNull(settings);

        var entitled = subscription.Status
            is SubscriptionStatus.Active
            or SubscriptionStatus.Trialing
            or SubscriptionStatus.PastDue;

        return entitled && !string.IsNullOrWhiteSpace(subscription.PlanId)
            ? subscription.PlanId
            : settings.FreePlanId;
    }
}

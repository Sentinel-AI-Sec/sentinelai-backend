namespace SentinelAI.Domain.Enums;

/// <summary>
/// Where a tenant's subscription stands, in Stripe's vocabulary rather than our own.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not a superset of Stripe's status list. Stripe distinguishes <c>unpaid</c> from
/// <c>past_due</c> (it has stopped retrying the card versus it is still retrying) and
/// <c>incomplete_expired</c> from <c>canceled</c> (the first payment never succeeded versus a
/// live subscription was ended). Both distinctions matter to a billing operator reading the
/// Stripe dashboard and neither changes anything this product does or shows, so
/// <c>BillingEventReader</c> folds them into the nearest member here and the dashboard stays the
/// place to find out which it was. Inventing members we would render identically would put a
/// word on the screen that no code branches on.
/// </para>
/// <para>
/// <see cref="None"/> is not a Stripe status. It is what a tenant that has never checked out
/// has, and it exists so "on the free tier" is a state the row can hold rather than the absence
/// of a row — see <c>SubscriptionView.From</c>, which answers it for a tenant with no row at all.
/// </para>
/// </remarks>
public enum SubscriptionStatus
{
    /// <summary>Never subscribed. The free tier, which every account starts on.</summary>
    None,

    /// <summary>Checkout finished but the first payment has not settled.</summary>
    Incomplete,

    /// <summary>Inside a free trial. Entitled to the plan; nothing has been charged yet.</summary>
    Trialing,

    /// <summary>Paid and current.</summary>
    Active,

    /// <summary>A renewal failed. Covers Stripe's <c>unpaid</c> as well — both mean the card did not work.</summary>
    PastDue,

    /// <summary>Ended. Covers Stripe's <c>incomplete_expired</c>, which is a subscription that never started.</summary>
    Canceled
}

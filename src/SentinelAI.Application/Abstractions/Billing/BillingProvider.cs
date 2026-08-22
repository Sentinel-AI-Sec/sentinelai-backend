namespace SentinelAI.Application.Abstractions.Billing;

/// <summary>
/// Which payment processor this deployment is wired to.
/// </summary>
/// <remarks>
/// <para>
/// The same shape as <c>SentinelAI:Models:Provider</c>, and for the same reason: a fresh clone has
/// to be able to run the whole product without credentials, or the offline demo and the
/// integration suite both become hostage to a commercial account somebody has to go and create.
/// </para>
/// <para>
/// <b>Which one is in force is reported to the client, not just logged.</b> A simulated gateway
/// that is indistinguishable from a real one at the API boundary is a trap: the difference between
/// "this customer paid" and "this customer clicked a button on a fake page" is the entire meaning
/// of the subscription record. <c>SubscriptionView.provider</c> carries it so the billing screen
/// can say so on the page rather than in a log nobody reads.
/// </para>
/// </remarks>
public enum BillingProvider
{
    /// <summary>
    /// Nothing is configured. The billing endpoints answer <c>503</c> with an honest reason.
    /// </summary>
    None,

    /// <summary>
    /// A local stand-in: real checkout flow, real webhook, real signature, no money.
    /// </summary>
    /// <remarks>
    /// Deliberately not a stub that flips a database column. It issues a hosted page, redirects
    /// back, and promotes the tenant only through a signed delivery to the same webhook endpoint
    /// Stripe posts to — so what the offline demo exercises is the real sequence, including the
    /// rule that a browser landing on the success URL proves nothing.
    /// </remarks>
    Simulated,

    /// <summary>Stripe, against a real account.</summary>
    Stripe,
}

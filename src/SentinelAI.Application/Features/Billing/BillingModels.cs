using System.Text.Json.Serialization;
using SentinelAI.Domain.Enums;
using SubscriptionEntity = SentinelAI.Domain.Models.Subscription;

namespace SentinelAI.Application.Features.Billing;

/// <summary>
/// The billing API's wire shapes, transcribed from the UI's <c>core/api/billing-api.ts</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>These names are a contract with another repository.</b> The Angular billing and pricing
/// screens were written against them before this controller existed, so a rename here is a
/// breaking change over there — which is why every property carries an explicit
/// <see cref="JsonPropertyNameAttribute"/> rather than trusting a serializer setting, exactly as
/// the SEC-40 read models do.
/// </para>
/// <para>
/// Snake case for the fields, inside the camel-cased <c>Response</c> envelope. That mismatch is
/// inherited rather than chosen: the envelope is the older convention and the UI's
/// <c>ResponseEnvelope&lt;T&gt;</c> already expects it, while the payload follows the newer
/// design-document convention the same UI's <c>wire.ts</c> is built on.
/// </para>
/// </remarks>
internal static class BillingWire
{
    /// <summary>
    /// Status as the UI spells it: <c>none | incomplete | trialing | active | past_due | canceled</c>.
    /// </summary>
    /// <remarks>
    /// Not <c>ToLowerInvariant()</c>, which the SEC-40 views can get away with because none of
    /// their enum members are two words. <see cref="SubscriptionStatus.PastDue"/> is, and
    /// lower-casing it yields <c>pastdue</c> — a value the UI's status union does not contain, so
    /// TypeScript would narrow it to the default branch and every failed payment would render as
    /// "Free tier" with no error anywhere.
    /// </remarks>
    public static string Of(SubscriptionStatus status) => status switch
    {
        SubscriptionStatus.None => "none",
        SubscriptionStatus.Incomplete => "incomplete",
        SubscriptionStatus.Trialing => "trialing",
        SubscriptionStatus.Active => "active",
        SubscriptionStatus.PastDue => "past_due",
        SubscriptionStatus.Canceled => "canceled",
        _ => throw new ArgumentOutOfRangeException(
            nameof(status), status, "No wire spelling for this subscription status."),
    };

    public static string Of(BillingPeriod period) => period.ToString().ToLowerInvariant();

    /// <summary>
    /// Stamps a timestamp as UTC so it serializes with a trailing <c>Z</c>.
    /// </summary>
    /// <remarks>
    /// Every date in this table is written in UTC, but SQL Server's <c>datetime2</c> stores no
    /// offset, so a value read back has <see cref="DateTimeKind.Unspecified"/> and
    /// <c>System.Text.Json</c> writes it without a zone. The browser's <c>Date</c> then parses it
    /// as <em>local</em> time — which silently moves a renewal date by hours, in whichever
    /// direction the reader's timezone happens to be, and is wrong on exactly the screen where a
    /// date is the thing the customer came to check.
    /// </remarks>
    public static DateTime? Utc(DateTime? value) =>
        value is null ? null : DateTime.SpecifyKind(value.Value, DateTimeKind.Utc);
}

/// <summary>
/// GET <c>/v1/billing/subscription</c> — what this tenant is on right now.
/// </summary>
/// <remarks>
/// Answered for a tenant with no subscription row at all, which is the normal state of a new
/// account. <see cref="From(SubscriptionEntity?)"/> collapses "no row" and a row holding only a
/// Stripe customer id into the same free-tier answer, so no caller has to know which of the two
/// it is looking at.
/// </remarks>
public sealed record SubscriptionView
{
    /// <summary>
    /// The plan id from the UI's <c>core/billing/plans.ts</c>, or null on nothing paid.
    /// </summary>
    /// <remarks>
    /// Null rather than the free plan's id, because the UI already resolves null to the free
    /// tier and null is the honest answer: nobody has bought anything. Returning
    /// <c>"developer"</c> would make a tenant that has never opened the billing screen
    /// indistinguishable from one whose paid plan lapsed back to free.
    /// </remarks>
    [JsonPropertyName("plan_id")] public string? PlanId { get; init; }

    [JsonPropertyName("status")] public required string Status { get; init; }

    [JsonPropertyName("period")] public string? Period { get; init; }

    [JsonPropertyName("quantity")] public required int Quantity { get; init; }

    /// <summary>The renewal date, or the cut-off when <see cref="CancelAtPeriodEnd"/> is set.</summary>
    [JsonPropertyName("current_period_end")] public DateTime? CurrentPeriodEnd { get; init; }

    [JsonPropertyName("cancel_at_period_end")] public required bool CancelAtPeriodEnd { get; init; }

    [JsonPropertyName("trial_end")] public DateTime? TrialEnd { get; init; }

    public static SubscriptionView From(SubscriptionEntity? subscription)
    {
        if (subscription is null || subscription.Status == SubscriptionStatus.None)
        {
            return new SubscriptionView
            {
                PlanId = null,
                Status = BillingWire.Of(SubscriptionStatus.None),
                Quantity = 0,
                CancelAtPeriodEnd = false,
            };
        }

        return new SubscriptionView
        {
            // Empty is not a plan. A row can hold a status without a plan id if a price was
            // retired from configuration while a customer was still subscribed to it, and null
            // renders as the free tier rather than as a plan the UI has no entry for.
            PlanId = string.IsNullOrWhiteSpace(subscription.PlanId) ? null : subscription.PlanId,
            Status = BillingWire.Of(subscription.Status),
            Period = subscription.Period is { } period ? BillingWire.Of(period) : null,
            Quantity = subscription.Quantity,
            CurrentPeriodEnd = BillingWire.Utc(subscription.CurrentPeriodEnd),
            CancelAtPeriodEnd = subscription.CancelAtPeriodEnd,

            // Only while actually trialing. Stripe leaves the date on the subscription after a
            // trial converts, and reporting it then would put "trial ends" on the screen of a
            // customer who is already paying.
            TrialEnd = subscription.Status == SubscriptionStatus.Trialing
                ? BillingWire.Utc(subscription.TrialEnd)
                : null,
        };
    }
}

/// <summary>
/// What a session-creating endpoint returns: somewhere to send the browser.
/// </summary>
/// <remarks>
/// Both <c>POST /v1/billing/checkout</c> and <c>POST /v1/billing/portal</c> answer this shape,
/// because from the UI's side they are the same action — leave the app, come back later. The
/// URL is Stripe's and is single-use.
/// </remarks>
public sealed record HostedSessionResponse
{
    [JsonPropertyName("url")] public required string Url { get; init; }
}

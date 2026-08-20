using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Application.Features.Billing;
using SentinelAI.Domain.Enums;
using SubscriptionEntity = SentinelAI.Domain.Models.Subscription;

namespace SentinelAI.Application.Tests.Billing;

/// <summary>
/// The three billing rules that are pure functions: the price allowlist, the return-origin check,
/// and what a subscription's status entitles a tenant to.
/// </summary>
/// <remarks>
/// The endpoint tests already drive all three over HTTP. These exist because each is a decision
/// with cases that a happy-path request never reaches — a retired price, a downgraded scheme, a
/// card that failed once — and pinning those needs a table, not a web host.
/// </remarks>
public class BillingRulesTests
{
    private const string TeamMonthly = "price_team_monthly";
    private const string TeamAnnual = "price_team_annual";

    private static PlanCatalog Catalog() => new(
    [
        new PlanPrice("team", BillingPeriod.Monthly, TeamMonthly),
        new PlanPrice("team", BillingPeriod.Annual, TeamAnnual),
    ]);

    private static BillingSettings Settings(params string[] origins) => new()
    {
        Plans = Catalog(),
        AllowedReturnOrigins = origins,
        FreePlanId = "free",
        IsConfigured = true,
    };

    // ---- the allowlist -----------------------------------------------------------------

    [Fact]
    public void A_plan_is_matched_case_insensitively_but_a_price_is_not()
    {
        // Plan ids are typed by people, into configuration and into a request body. Price ids are
        // opaque Stripe identifiers where a case difference means a different object, so matching
        // them loosely would be inventing an equivalence Stripe does not have.
        Assert.Equal(TeamMonthly, Catalog().Find("TEAM", BillingPeriod.Monthly)?.PriceId);
        Assert.Null(Catalog().FindByPriceId(TeamMonthly.ToUpperInvariant()));
    }

    [Fact]
    public void A_cadence_this_deployment_does_not_sell_resolves_to_nothing()
    {
        var catalog = new PlanCatalog([new PlanPrice("team", BillingPeriod.Monthly, TeamMonthly)]);

        Assert.NotNull(catalog.Find("team", BillingPeriod.Monthly));
        Assert.Null(catalog.Find("team", BillingPeriod.Annual));
    }

    [Fact]
    public void A_price_with_no_plan_configured_for_it_resolves_to_nothing()
    {
        // The answer the webhook depends on. Guessing a plan for an unrecognised price would
        // grant an entitlement nobody configured — and price ids are public identifiers.
        Assert.Null(Catalog().FindByPriceId("price_one_cent"));
    }

    [Fact]
    public void Blank_entries_are_dropped_rather_than_sold()
    {
        // The shipped appsettings.json ships the plan keys with empty price ids, so that a
        // deployment can see the shape it has to fill in. An empty id must not be purchasable:
        // it would reach Stripe as a missing price and fail there instead of here.
        var catalog = new PlanCatalog(
        [
            new PlanPrice("team", BillingPeriod.Monthly, "   "),
            new PlanPrice("", BillingPeriod.Annual, TeamAnnual),
        ]);

        Assert.False(catalog.IsConfigured);
        Assert.Empty(catalog.Prices);
    }

    // ---- the return-origin check -------------------------------------------------------

    [Theory]
    [InlineData("https://ui.test/billing?checkout=success", true)]
    [InlineData("https://ui.test", true)]
    [InlineData("http://ui.test/billing", false)]
    [InlineData("https://ui.test.evil.com/billing", false)]
    [InlineData("https://evil.com/?x=https://ui.test", false)]
    [InlineData("//ui.test/billing", false)]
    [InlineData("javascript:alert(1)", false)]
    [InlineData(null, false)]
    public void Only_a_configured_origin_may_be_returned_to(string? url, bool allowed)
    {
        // Each false is a distinct way an open redirect is usually let through: a downgraded
        // scheme, a suffix that merely starts with the allowed host, the allowed origin appearing
        // in a query string, a protocol-relative URL, and a scheme that is not a redirect at all.
        Assert.Equal(allowed, Settings("https://ui.test").IsAllowedReturnUrl(url));
    }

    [Fact]
    public void An_empty_allowlist_refuses_everything()
    {
        // Matches how Cors:AllowedOrigins behaves, and for the same reason: a deployment that
        // forgets to configure this gets a checkout that visibly does not start, rather than one
        // that will redirect anywhere.
        Assert.False(Settings().IsAllowedReturnUrl("https://ui.test/billing"));
    }

    [Fact]
    public void A_default_port_is_the_same_origin_as_none()
    {
        // Uri normalises :443 away on https, so a configured origin and a browser-sent URL that
        // disagree only about the default port are the same origin and must not be refused.
        Assert.True(Settings("https://ui.test").IsAllowedReturnUrl("https://ui.test:443/billing"));

        // A non-default port is a different origin, which is what the check is for.
        Assert.False(Settings("https://ui.test").IsAllowedReturnUrl("https://ui.test:8443/billing"));
    }

    // ---- entitlement -------------------------------------------------------------------

    [Theory]
    [InlineData(SubscriptionStatus.Active, "team")]
    [InlineData(SubscriptionStatus.Trialing, "team")]
    [InlineData(SubscriptionStatus.PastDue, "team")]
    [InlineData(SubscriptionStatus.Incomplete, "free")]
    [InlineData(SubscriptionStatus.Canceled, "free")]
    [InlineData(SubscriptionStatus.None, "free")]
    public void Status_decides_the_tier(SubscriptionStatus status, string expected)
    {
        // PastDue keeps the plan on purpose: it is a card that failed once while Stripe is still
        // retrying, not a lapsed account. Incomplete does not: the first payment never succeeded,
        // so there is nothing to give the benefit of the doubt to.
        var subscription = new SubscriptionEntity { PlanId = "team", Status = status };

        Assert.Equal(expected, BillingEntitlement.TierFor(subscription, Settings()));
    }

    [Fact]
    public void A_pending_cancellation_stays_entitled_until_Stripe_ends_it()
    {
        // The customer has paid through CurrentPeriodEnd. Acting on the flag early would charge
        // for a period and then withhold it; Stripe sends its own event when the time comes.
        var subscription = new SubscriptionEntity
        {
            PlanId = "team",
            Status = SubscriptionStatus.Active,
            CancelAtPeriodEnd = true,
            CurrentPeriodEnd = DateTime.UtcNow.AddDays(12),
        };

        Assert.Equal("team", BillingEntitlement.TierFor(subscription, Settings()));
    }

    [Fact]
    public void An_active_subscription_with_no_plan_falls_back_to_free_rather_than_to_empty()
    {
        // Reachable: a price retired from configuration while somebody was still subscribed to
        // it. An empty tier is a value no feature gate has a case for, so it would be read as
        // "not the paid tier" by some checks and as a missing value by others.
        var subscription = new SubscriptionEntity
        {
            PlanId = string.Empty,
            Status = SubscriptionStatus.Active,
        };

        Assert.Equal("free", BillingEntitlement.TierFor(subscription, Settings()));
    }

    // ---- the wire shape ----------------------------------------------------------------

    [Fact]
    public void A_missing_subscription_and_a_row_holding_only_a_customer_id_read_the_same()
    {
        // A tenant that never opened the billing screen has no row; one that abandoned a payment
        // page has a row carrying a Stripe customer and nothing else. Both are the free tier, and
        // no caller should have to know which it is looking at.
        var abandoned = new SubscriptionEntity
        {
            Status = SubscriptionStatus.None,
            StripeCustomerId = "cus_abandoned",
        };

        var fromNothing = SubscriptionView.From(null);
        var fromRow = SubscriptionView.From(abandoned);

        Assert.Equal("none", fromNothing.Status);
        Assert.Equal(fromNothing.Status, fromRow.Status);
        Assert.Null(fromNothing.PlanId);
        Assert.Null(fromRow.PlanId);
    }

    [Fact]
    public void A_trial_end_date_is_only_reported_while_actually_trialing()
    {
        // Stripe leaves the date on the subscription after a trial converts. Reporting it then
        // puts "trial ends" on the screen of a customer who is already paying.
        var trialEnd = DateTime.UtcNow.AddDays(5);

        var trialing = SubscriptionView.From(new SubscriptionEntity
        {
            PlanId = "team", Status = SubscriptionStatus.Trialing, TrialEnd = trialEnd,
        });

        var converted = SubscriptionView.From(new SubscriptionEntity
        {
            PlanId = "team", Status = SubscriptionStatus.Active, TrialEnd = trialEnd,
        });

        Assert.NotNull(trialing.TrialEnd);
        Assert.Null(converted.TrialEnd);
    }

    [Fact]
    public void Dates_cross_the_wire_stamped_as_UTC()
    {
        // SQL Server datetime2 stores no offset, so a value read back is Unspecified and would
        // serialize without a trailing Z — which the browser then parses as local time, silently
        // moving a renewal date by hours on the one screen where the date is the point.
        var view = SubscriptionView.From(new SubscriptionEntity
        {
            PlanId = "team",
            Status = SubscriptionStatus.Active,
            CurrentPeriodEnd = new DateTime(2026, 9, 20, 10, 0, 0, DateTimeKind.Unspecified),
        });

        Assert.Equal(DateTimeKind.Utc, view.CurrentPeriodEnd!.Value.Kind);
    }
}

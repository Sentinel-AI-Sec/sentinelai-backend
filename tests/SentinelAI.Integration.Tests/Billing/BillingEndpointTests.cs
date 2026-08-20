using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Billing;

/// <summary>
/// The four billing endpoints through the real API — real JWT pipeline, real role gates, real
/// tenant query filter, and a real Stripe webhook signature.
/// </summary>
/// <remarks>
/// <para>
/// <b>Driven over HTTP rather than against the handlers.</b> Every defect this feature can have
/// lives in a join: the webhook against the tenant query filter, the checkout body against the
/// price allowlist, the return URL against the CORS origins. Each component is correct read on
/// its own, and only the composition can be wrong — so the composition is what is exercised, with
/// the state asserted by reading the database back rather than by trusting the response.
/// </para>
/// <para>
/// A fresh factory per test class instance, because these assert on absolute row state.
/// </para>
/// </remarks>
public sealed class BillingEndpointTests : IClassFixture<BillingApiFactory>
{
    private readonly BillingApiFactory _factory;

    public BillingEndpointTests(BillingApiFactory factory) => _factory = factory;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private HttpClient ClientFor(Guid tenantId, string role = Roles.Admin, Guid? userId = null) =>
        Authorized(TestJwt.Create(tenantId, userId ?? Guid.CreateVersion7(), role));

    private HttpClient Authorized(string? token)
    {
        var client = _factory.CreateClient();

        if (token is not null)
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        return client;
    }

    /// <summary>A tenant with a user who can be billed, and no subscription yet.</summary>
    private async Task<Guid> SeedTenantAsync(Guid tenantId, Guid userId)
    {
        await _factory.SeedAsync(db => db.Users.Add(new User
        {
            Id = userId,
            TenantId = tenantId,
            Email = $"{tenantId:N}@example.test",
            PasswordHash = "hash",
            Role = Roles.Admin,
            CreatedAt = DateTime.UtcNow,
        }));

        return tenantId;
    }

    /// <summary>A tenant already subscribed, as a completed checkout would have left it.</summary>
    private async Task SeedSubscriptionAsync(
        Guid tenantId,
        string customerId,
        SubscriptionStatus status = SubscriptionStatus.Active,
        string planId = "team",
        DateTime? lastEventAt = null)
    {
        await _factory.SeedAsync(db => db.Subscriptions.Add(new Subscription
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            PlanId = planId,
            Period = BillingPeriod.Monthly,
            Status = status,
            Quantity = 1,
            StripeCustomerId = customerId,
            StripeSubscriptionId = $"sub_for_{customerId}",
            LastEventAt = lastEventAt,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
        }));
    }

    private async Task<Subscription?> ReadSubscriptionAsync(Guid tenantId)
    {
        using var scope = _factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();

        return await db.Subscriptions
            .IgnoreQueryFilters()
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.TenantId == tenantId);
    }

    private async Task<string?> ReadPlanTierAsync(Guid tenantId)
    {
        using var scope = _factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();

        return await db.Tenants
            .AsNoTracking()
            .Where(t => t.Id == tenantId)
            .Select(t => t.PlanTier)
            .FirstOrDefaultAsync();
    }

    // ---- reads -------------------------------------------------------------------------

    [Fact]
    public async Task An_anonymous_caller_cannot_read_a_subscription()
    {
        var response = await Authorized(null).GetAsync("/v1/billing/subscription");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_tenant_that_has_never_paid_reads_as_the_free_tier_not_as_a_404()
    {
        // "No subscription" is a plan. A screen forced to treat a missing resource as a business
        // state will eventually treat a network failure as one too.
        var tenantId = Guid.CreateVersion7();
        await SeedTenantAsync(tenantId, Guid.CreateVersion7());

        var response = await ClientFor(tenantId).GetAsync("/v1/billing/subscription");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var view = await ReadViewAsync(response);

        Assert.Null(view.GetProperty("plan_id").GetString());
        Assert.Equal("none", view.GetProperty("status").GetString());
        Assert.False(view.GetProperty("cancel_at_period_end").GetBoolean());
    }

    [Fact]
    public async Task A_subscription_is_read_in_the_wire_shape_the_UI_was_written_against()
    {
        // snake_case field names and lower-cased status words, transcribed from the UI's
        // core/api/billing-api.ts. A rename here is a breaking change in another repository, so
        // it is pinned rather than assumed.
        var tenantId = Guid.CreateVersion7();
        await SeedTenantAsync(tenantId, Guid.CreateVersion7());
        await SeedSubscriptionAsync(tenantId, $"cus_{tenantId:N}", SubscriptionStatus.PastDue);

        var response = await ClientFor(tenantId).GetAsync("/v1/billing/subscription");
        var view = await ReadViewAsync(response);

        Assert.Equal("team", view.GetProperty("plan_id").GetString());

        // Not "pastdue". A plain ToLowerInvariant() would produce a word the UI's status union
        // does not contain, and every failed payment would render as "Free tier".
        Assert.Equal("past_due", view.GetProperty("status").GetString());
        Assert.Equal("monthly", view.GetProperty("period").GetString());
        Assert.Equal(1, view.GetProperty("quantity").GetInt32());
    }

    [Fact]
    public async Task One_tenant_cannot_read_another_tenants_subscription()
    {
        var mine = Guid.CreateVersion7();
        var theirs = Guid.CreateVersion7();

        await SeedTenantAsync(mine, Guid.CreateVersion7());
        await SeedTenantAsync(theirs, Guid.CreateVersion7());
        await SeedSubscriptionAsync(theirs, $"cus_{theirs:N}");

        var response = await ClientFor(mine).GetAsync("/v1/billing/subscription");
        var view = await ReadViewAsync(response);

        // Not filtered out of the result — never in it. The only tenant the query knows is the
        // one on the verified token.
        Assert.Null(view.GetProperty("plan_id").GetString());
        Assert.Equal("none", view.GetProperty("status").GetString());
    }

    // ---- checkout ----------------------------------------------------------------------

    [Theory]
    [InlineData(Roles.Viewer)]
    [InlineData(Roles.Analyst)]
    public async Task A_non_admin_cannot_start_a_checkout(string role)
    {
        var tenantId = Guid.CreateVersion7();
        await SeedTenantAsync(tenantId, Guid.CreateVersion7());

        var response = await ClientFor(tenantId, role).PostAsJsonAsync(
            "/v1/billing/checkout", Checkout());

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Checkout_resolves_the_plan_to_the_configured_price()
    {
        var tenantId = Guid.CreateVersion7();
        var userId = Guid.CreateVersion7();
        await SeedTenantAsync(tenantId, userId);

        var response = await ClientFor(tenantId, userId: userId)
            .PostAsJsonAsync("/v1/billing/checkout", Checkout(period: "annual"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var request = Assert.Single(_factory.Gateway.CheckoutRequests);
        Assert.Equal(BillingApiFactory.TeamAnnualPriceId, request.PriceId);
        Assert.Equal(tenantId, request.TenantId);

        _factory.Gateway.CheckoutRequests.Clear();
    }

    [Fact]
    public async Task A_plan_this_deployment_does_not_sell_is_refused_before_Stripe_is_called()
    {
        // 'enterprise' is priced by conversation and has no entry in Billing:Prices. The point of
        // resolving name-to-price against configuration is that the set of purchasable things is
        // exactly what an operator wrote down.
        var tenantId = Guid.CreateVersion7();
        var userId = Guid.CreateVersion7();
        await SeedTenantAsync(tenantId, userId);

        var before = _factory.Gateway.CheckoutRequests.Count;

        var response = await ClientFor(tenantId, userId: userId)
            .PostAsJsonAsync("/v1/billing/checkout", Checkout(planId: "enterprise"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, _factory.Gateway.CheckoutRequests.Count);
    }

    [Theory]
    [InlineData("https://evil.test/steal")]
    [InlineData("http://ui.sentinelai.test/billing")]
    public async Task A_return_url_outside_the_allowed_origins_is_refused(string successUrl)
    {
        // An unchecked return URL on an endpoint anybody authenticated can reach is an open
        // redirect: a link to our own API that bounces the victim to an attacker's page, arriving
        // with our domain in the referrer. The http:// case matters too — the origin comparison
        // includes the scheme, so downgrading it must not pass.
        var tenantId = Guid.CreateVersion7();
        var userId = Guid.CreateVersion7();
        await SeedTenantAsync(tenantId, userId);

        var before = _factory.Gateway.CheckoutRequests.Count;

        var response = await ClientFor(tenantId, userId: userId).PostAsJsonAsync(
            "/v1/billing/checkout", Checkout(successUrl: successUrl));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, _factory.Gateway.CheckoutRequests.Count);
    }

    [Fact]
    public async Task Checkout_stores_the_Stripe_customer_before_returning()
    {
        // If the id is not persisted, the next attempt mints a second Stripe customer and one
        // organisation's invoices end up split across two — with the billing portal only ever
        // showing whichever it was last handed.
        var tenantId = Guid.CreateVersion7();
        var userId = Guid.CreateVersion7();
        await SeedTenantAsync(tenantId, userId);

        _factory.Gateway.CustomerId = $"cus_first_{tenantId:N}";

        var client = ClientFor(tenantId, userId: userId);
        await client.PostAsJsonAsync("/v1/billing/checkout", Checkout());

        var stored = await ReadSubscriptionAsync(tenantId);
        Assert.NotNull(stored);
        Assert.Equal($"cus_first_{tenantId:N}", stored!.StripeCustomerId);

        // Nothing has been granted: a checkout that has not been paid for is not a plan.
        Assert.Equal(SubscriptionStatus.None, stored.Status);

        // A second attempt reuses it rather than creating a second customer.
        _factory.Gateway.CustomerId = "cus_second_should_not_be_used";
        await client.PostAsJsonAsync("/v1/billing/checkout", Checkout());

        var after = await ReadSubscriptionAsync(tenantId);
        Assert.Equal($"cus_first_{tenantId:N}", after!.StripeCustomerId);

        _factory.Gateway.CheckoutRequests.Clear();
    }

    // ---- portal ------------------------------------------------------------------------

    [Fact]
    public async Task The_portal_opens_the_callers_own_customer()
    {
        var tenantId = Guid.CreateVersion7();
        await SeedTenantAsync(tenantId, Guid.CreateVersion7());
        await SeedSubscriptionAsync(tenantId, $"cus_portal_{tenantId:N}");

        var response = await ClientFor(tenantId).PostAsJsonAsync(
            "/v1/billing/portal", new { returnUrl = $"{BillingApiFactory.AllowedOrigin}/billing" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // A portal session is full control over a Stripe customer — cards, invoices,
        // cancellation. The customer id must come from the token's tenant, never from the body.
        Assert.Contains($"cus_portal_{tenantId:N}", _factory.Gateway.PortalRequests);

        _factory.Gateway.PortalRequests.Clear();
    }

    [Fact]
    public async Task A_tenant_with_no_billing_account_is_told_so_rather_than_404()
    {
        var tenantId = Guid.CreateVersion7();
        await SeedTenantAsync(tenantId, Guid.CreateVersion7());

        var response = await ClientFor(tenantId).PostAsJsonAsync(
            "/v1/billing/portal", new { returnUrl = $"{BillingApiFactory.AllowedOrigin}/billing" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---- webhook -----------------------------------------------------------------------

    [Fact]
    public async Task An_unsigned_webhook_is_refused()
    {
        // This endpoint is the only thing in the API that can grant a paid plan, and the
        // signature is the only authentication it has.
        var response = await PostWebhookAsync(SubscriptionEvent("cus_nobody"), signature: null);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_webhook_signed_with_the_wrong_secret_is_refused()
    {
        var payload = SubscriptionEvent("cus_nobody");
        var forged = BillingApiFactory.Sign(payload, secret: "whsec_attacker_guess");

        var response = await PostWebhookAsync(payload, forged);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_replayed_webhook_outside_the_tolerance_is_refused()
    {
        // The HMAC over an old payload stays valid forever, so recency is a separate check. A
        // delivery captured off the wire and replayed a day later must not still promote a plan.
        var payload = SubscriptionEvent("cus_nobody");
        var stale = BillingApiFactory.Sign(payload, timestamp: DateTimeOffset.UtcNow.AddHours(-1));

        var response = await PostWebhookAsync(payload, stale);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_signed_subscription_event_grants_the_plan_despite_the_tenant_query_filter()
    {
        // THE test for this feature. The webhook is unauthenticated, so SentinelDbContext resolves
        // CurrentTenantId to Guid.Empty and the query filter on Subscription matches nothing.
        // Query filters do not affect writes, so a handler reading through the ordinary repository
        // would find no row, decide there was nothing to do, and answer 200 — Stripe would mark
        // the delivery handled and never retry. Customers pay, Stripe shows them as active, and
        // the product keeps every one of them on the free tier with no error anywhere.
        var tenantId = Guid.CreateVersion7();
        var customerId = $"cus_grant_{tenantId:N}";

        await SeedTenantAsync(tenantId, Guid.CreateVersion7());
        await SeedSubscriptionAsync(tenantId, customerId, SubscriptionStatus.None, planId: string.Empty);

        var payload = SubscriptionEvent(customerId, quantity: 4);
        var response = await PostWebhookAsync(payload, BillingApiFactory.Sign(payload));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var subscription = await ReadSubscriptionAsync(tenantId);
        Assert.Equal(SubscriptionStatus.Active, subscription!.Status);
        Assert.Equal("team", subscription.PlanId);
        Assert.Equal(BillingPeriod.Monthly, subscription.Period);
        Assert.Equal(4, subscription.Quantity);

        // And the entitlement the rest of the product gates on moved with it. Writing one without
        // the other produces an account billed for Team and gated as free, invisible until a
        // customer complains — each table is self-consistent on its own.
        Assert.Equal("team", await ReadPlanTierAsync(tenantId));
    }

    [Fact]
    public async Task The_plan_comes_from_the_price_Stripe_billed_not_from_what_was_asked_for()
    {
        // A price this deployment does not sell cannot grant a plan. Otherwise a subscription
        // created against any price — they are public identifiers — would provision whatever the
        // last checkout request happened to name.
        var tenantId = Guid.CreateVersion7();
        var customerId = $"cus_unknownprice_{tenantId:N}";

        await SeedTenantAsync(tenantId, Guid.CreateVersion7());
        await SeedSubscriptionAsync(tenantId, customerId, SubscriptionStatus.None, planId: string.Empty);

        var payload = SubscriptionEvent(customerId, priceId: "price_one_cent_attacker");
        var response = await PostWebhookAsync(payload, BillingApiFactory.Sign(payload));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var subscription = await ReadSubscriptionAsync(tenantId);
        Assert.Equal(string.Empty, subscription!.PlanId);
        Assert.Equal("free", await ReadPlanTierAsync(tenantId));
    }

    [Fact]
    public async Task An_event_for_a_customer_nobody_owns_is_acknowledged_and_changes_nothing()
    {
        // Answering non-2xx makes Stripe retry for three days and then disable the endpoint,
        // taking the deliveries that matter down with it.
        var payload = SubscriptionEvent("cus_belongs_to_no_tenant");

        var response = await PostWebhookAsync(payload, BillingApiFactory.Sign(payload));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task An_overtaken_webhook_cannot_revert_a_newer_state()
    {
        // Stripe delivers at least once and does not guarantee order, and each event carries the
        // whole subscription rather than a delta — so a redelivered older event would rewrite the
        // row with a state that has since been superseded. The customer would appear to be back
        // on the plan they left, with Stripe showing the right one the whole time.
        var tenantId = Guid.CreateVersion7();
        var customerId = $"cus_ordering_{tenantId:N}";
        var now = DateTime.UtcNow;

        await SeedTenantAsync(tenantId, Guid.CreateVersion7());
        await SeedSubscriptionAsync(
            tenantId, customerId, SubscriptionStatus.Active, lastEventAt: now);

        var stale = SubscriptionEvent(
            customerId, status: "canceled", createdAt: now.AddMinutes(-10));

        var response = await PostWebhookAsync(stale, BillingApiFactory.Sign(stale));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var subscription = await ReadSubscriptionAsync(tenantId);
        Assert.Equal(SubscriptionStatus.Active, subscription!.Status);
    }

    [Fact]
    public async Task A_cancelled_subscription_drops_the_tenant_back_to_the_free_tier()
    {
        var tenantId = Guid.CreateVersion7();
        var customerId = $"cus_cancel_{tenantId:N}";

        await SeedTenantAsync(tenantId, Guid.CreateVersion7());
        await SeedSubscriptionAsync(tenantId, customerId, SubscriptionStatus.Active);

        var payload = SubscriptionEvent(customerId, status: "canceled");
        await PostWebhookAsync(payload, BillingApiFactory.Sign(payload));

        var subscription = await ReadSubscriptionAsync(tenantId);
        Assert.Equal(SubscriptionStatus.Canceled, subscription!.Status);

        // Back to the literal RegisterCommandHandler writes for a new tenant — not a synonym for
        // it, or every feature gate needs a second case.
        Assert.Equal("free", await ReadPlanTierAsync(tenantId));
    }

    [Fact]
    public async Task A_failed_payment_keeps_the_plan_and_says_so()
    {
        // past_due is a card that failed once while Stripe is still retrying, which is the window
        // in which a customer can fix it. Locking a paying customer out of a security product
        // over an expired card, hours before the replacement charge succeeds, is the wrong call.
        var tenantId = Guid.CreateVersion7();
        var customerId = $"cus_pastdue_{tenantId:N}";

        await SeedTenantAsync(tenantId, Guid.CreateVersion7());
        await SeedSubscriptionAsync(tenantId, customerId, SubscriptionStatus.Active);

        var payload = InvoiceFailedEvent(customerId);
        await PostWebhookAsync(payload, BillingApiFactory.Sign(payload));

        var subscription = await ReadSubscriptionAsync(tenantId);
        Assert.Equal(SubscriptionStatus.PastDue, subscription!.Status);
        Assert.Equal("team", await ReadPlanTierAsync(tenantId));
    }

    [Fact]
    public async Task An_event_type_this_product_ignores_is_acknowledged()
    {
        var payload = """
            {"id":"evt_ignored","object":"event","api_version":"2025-01-01","created":%CREATED%,
             "type":"customer.created","data":{"object":{"id":"cus_x","object":"customer"}}}
            """.Replace("%CREATED%", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());

        var response = await PostWebhookAsync(payload, BillingApiFactory.Sign(payload));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ---- helpers -----------------------------------------------------------------------

    private static object Checkout(
        string planId = "team",
        string period = "monthly",
        string? successUrl = null) => new
        {
            planId,
            period,
            quantity = 1,
            successUrl = successUrl ?? $"{BillingApiFactory.AllowedOrigin}/billing?checkout=success",
            cancelUrl = $"{BillingApiFactory.AllowedOrigin}/billing?checkout=cancelled",
        };

    private async Task<HttpResponseMessage> PostWebhookAsync(string payload, string? signature)
    {
        var client = _factory.CreateClient();

        var content = new StringContent(payload, Encoding.UTF8, "application/json");
        if (signature is not null) content.Headers.Add("Stripe-Signature", signature);

        return await client.PostAsync("/v1/billing/webhook", content);
    }

    private static async Task<JsonElement> ReadViewAsync(HttpResponseMessage response)
    {
        var envelope = await response.Content.ReadFromJsonAsync<JsonElement>(Json);
        return envelope.GetProperty("data");
    }

    /// <summary>
    /// A <c>customer.subscription.updated</c> payload, in Stripe's own shape.
    /// </summary>
    /// <remarks>
    /// Hand-written rather than produced by the SDK, because it stands in for what actually
    /// arrives on the wire — including <c>current_period_end</c> living on the subscription
    /// <em>item</em>, which is where Stripe moved it and where reading the wrong one leaves every
    /// renewal date silently null.
    /// </remarks>
    private static string SubscriptionEvent(
        string customerId,
        string status = "active",
        string? priceId = null,
        int quantity = 1,
        DateTime? createdAt = null)
    {
        var created = new DateTimeOffset(createdAt ?? DateTime.UtcNow, TimeSpan.Zero).ToUnixTimeSeconds();
        var periodEnd = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds();

        return $$"""
            {
              "id": "evt_{{Guid.NewGuid():N}}",
              "object": "event",
              "api_version": "2025-01-01",
              "created": {{created}},
              "type": "customer.subscription.updated",
              "data": {
                "object": {
                  "id": "sub_{{customerId}}",
                  "object": "subscription",
                  "customer": "{{customerId}}",
                  "status": "{{status}}",
                  "cancel_at_period_end": false,
                  "items": {
                    "object": "list",
                    "data": [
                      {
                        "id": "si_test",
                        "object": "subscription_item",
                        "quantity": {{quantity}},
                        "current_period_end": {{periodEnd}},
                        "price": {
                          "id": "{{priceId ?? BillingApiFactory.TeamMonthlyPriceId}}",
                          "object": "price"
                        }
                      }
                    ]
                  }
                }
              }
            }
            """;
    }

    private static string InvoiceFailedEvent(string customerId) => $$"""
        {
          "id": "evt_{{Guid.NewGuid():N}}",
          "object": "event",
          "api_version": "2025-01-01",
          "created": {{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}},
          "type": "invoice.payment_failed",
          "data": {
            "object": {
              "id": "in_test",
              "object": "invoice",
              "customer": "{{customerId}}"
            }
          }
        }
        """;
}

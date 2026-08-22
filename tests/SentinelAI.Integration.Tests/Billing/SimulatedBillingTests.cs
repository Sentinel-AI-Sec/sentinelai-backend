using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Billing;
using SentinelAI.Integration.Tests.Auth;
using SentinelAI.Integration.Tests.Scan;

namespace SentinelAI.Integration.Tests.Billing;

/// <summary>
/// The whole upgrade flow, offline.
/// </summary>
/// <remarks>
/// <para>
/// This is the acceptance test for the simulated processor, and its point is that it goes the long
/// way round: checkout, the hosted page, the signed webhook, the entitlement, the quota. A test
/// that wrote a plan onto the tenant and asserted the plan was written would pass against a stub
/// that skipped everything worth having.
/// </para>
/// <para>
/// No Stripe account, no network, no keys — the same standard the offline agent demo holds itself
/// to.
/// </para>
/// </remarks>
public class SimulatedBillingTests : IDisposable
{
    private readonly ScanApiFactory _factory = new() { RealEntitlements = true };

    public void Dispose()
    {
        _factory.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// The test host with the simulated processor on and a return origin it will accept.
    /// </summary>
    /// <remarks>
    /// Layered rather than baked into <see cref="ScanApiFactory"/>: every other suite should see
    /// billing switched off, because a provider that answers is a provider that can change a
    /// tenant's plan underneath a test about something else.
    /// </remarks>
    private WebApplicationFactory<Program> Simulated() =>
        _factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Billing:Provider"] = "Simulated",
                    ["Billing:AllowedReturnOrigins:0"] = Origin,
                })));

    private const string Origin = "https://console.sentinelai.test";

    /// <summary>
    /// A tenant on a plan, an admin user, and a project to scan.
    /// </summary>
    /// <remarks>
    /// The user row is not decoration: checkout resolves the caller's email to put on the customer
    /// record, and a token whose <c>sub</c> matches no user is refused with "there is no one to
    /// bill" — which is the right answer, and one this suite has to satisfy rather than bypass.
    /// </remarks>
    private async Task<(Guid Tenant, Guid User, Guid Project)> SeedTenantAsync(string planTier)
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.CreateVersion7();
        var projectId = Guid.CreateVersion7();

        await _factory.SeedAsync(db =>
        {
            db.Tenants.Add(new Tenant
            {
                Id = tenantId,
                Name = $"tenant-{tenantId:N}",
                PlanTier = planTier,
                CreatedAt = DateTime.UtcNow,
            });

            db.Users.Add(new User
            {
                Id = userId,
                TenantId = tenantId,
                Email = $"admin-{userId:N}@example.test",
                PasswordHash = "x",
                Role = Roles.Admin,
                CreatedAt = DateTime.UtcNow,
            });

            db.Projects.Add(new Project
            {
                Id = projectId,
                TenantId = tenantId,
                RepoUrl = $"https://example.test/repo/{projectId}",
                DefaultBranch = "main",
            });
        });

        return (tenantId, userId, projectId);
    }

    private static HttpClient Authed(
        WebApplicationFactory<Program> host, Guid tenantId, Guid userId, string role, params string[] scopes)
    {
        var client = host.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", TestJwt.Create(tenantId, userId: userId, role: role, scopes: scopes));
        return client;
    }

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.Clone();
    }

    /// <summary>Runs checkout and returns the simulator URL the browser would be sent to.</summary>
    private static async Task<string> StartCheckoutAsync(HttpClient admin, string planId, string period = "Monthly")
    {
        var response = await admin.PostAsJsonAsync("/v1/billing/checkout", new
        {
            planId,
            period,
            quantity = 1,
            successUrl = $"{Origin}/billing?checkout=success",
            cancelUrl = $"{Origin}/billing?checkout=cancelled",
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return (await BodyAsync(response)).GetProperty("data").GetProperty("url").GetString()!;
    }

    // ---- the acceptance test ----------------------------------------------------------------

    /// <summary>
    /// Free tenant, refused a third scan, upgrades, and the refusal lifts — through the hosted
    /// page and the signed webhook, with nothing writing the plan directly.
    /// </summary>
    [Fact]
    public async Task An_upgrade_runs_end_to_end_with_no_stripe_account()
    {
        using var host = Simulated();
        var (tenant, user, _) = await SeedTenantAsync(PlanEntitlementCatalog.Free);
        var admin = Authed(host, tenant, user, Roles.Admin, AuthScopes.ScanWrite, AuthScopes.ScanRead);

        // Before: the free tier, reported as simulated so nobody mistakes it for a paid account.
        var before = await BodyAsync(await admin.GetAsync("/v1/billing/subscription"));
        Assert.Equal("none", before.GetProperty("data").GetProperty("status").GetString());
        Assert.Equal("simulated", before.GetProperty("data").GetProperty("provider").GetString());

        var checkoutUrl = await StartCheckoutAsync(admin, PlanEntitlementCatalog.Pro);
        Assert.Contains("/v1/billing/simulator/checkout", checkoutUrl);

        // The hosted page renders, and says plainly that no money moves.
        var page = await host.CreateClient().GetAsync(new Uri(checkoutUrl).PathAndQuery);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("No payment will be taken", await page.Content.ReadAsStringAsync());

        // Landing on the success URL without paying changes nothing. This is the rule the whole
        // flow is built around, so it is asserted before the payment rather than only after.
        var unpaid = await BodyAsync(await admin.GetAsync("/v1/billing/subscription"));
        Assert.Equal("none", unpaid.GetProperty("data").GetProperty("status").GetString());

        await CompleteAsync(host, checkoutUrl);

        var after = await BodyAsync(await admin.GetAsync("/v1/billing/subscription"));
        Assert.Equal(PlanEntitlementCatalog.Pro, after.GetProperty("data").GetProperty("plan_id").GetString());
        Assert.Equal("active", after.GetProperty("data").GetProperty("status").GetString());
    }

    /// <summary>
    /// The upgrade has to change what the tenant can <em>do</em>, not just what a screen says.
    /// </summary>
    [Fact]
    public async Task The_upgrade_lifts_the_daily_scan_limit()
    {
        using var host = Simulated();
        var (tenant, user, project) = await SeedTenantAsync(PlanEntitlementCatalog.Free);
        var admin = Authed(host, tenant, user, Roles.Admin, AuthScopes.ScanWrite, AuthScopes.ScanRead);

        Assert.Equal(HttpStatusCode.Accepted, (await SubmitAsync(admin, project, "sha1")).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await SubmitAsync(admin, project, "sha2")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await SubmitAsync(admin, project, "sha3")).StatusCode);

        await CompleteAsync(host, await StartCheckoutAsync(admin, PlanEntitlementCatalog.Pro));

        // Pro allows 20 a day and two are already spent, so the scan that was refused now runs.
        Assert.Equal(HttpStatusCode.Accepted, (await SubmitAsync(admin, project, "sha3")).StatusCode);
    }

    // ---- the rules that must survive being simulated ------------------------------------------

    /// <summary>
    /// A forged delivery grants nothing. The signature is the only authentication this endpoint
    /// has, and simulating the processor must not simulate away the check.
    /// </summary>
    [Fact]
    public async Task An_unsigned_webhook_is_refused()
    {
        using var host = Simulated();
        var client = host.CreateClient();

        var forged = JsonSerializer.Serialize(new
        {
            id = "sim_evt_forged",
            occurred_at = DateTime.UtcNow,
            kind = "SubscriptionChanged",
            customer = "sim_cus_whoever",
            price = "sim_price_max_monthly",
            status = "Active",
        });

        var response = await client.PostAsync(
            "/v1/billing/webhook", new StringContent(forged, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// The session token is sealed, so the price cannot be edited in the address bar into a
    /// cheaper — or free — one.
    /// </summary>
    [Fact]
    public async Task A_tampered_checkout_session_is_refused()
    {
        using var host = Simulated();
        var (tenant, user, _) = await SeedTenantAsync(PlanEntitlementCatalog.Free);
        var admin = Authed(host, tenant, user, Roles.Admin, AuthScopes.ScanWrite);

        var url = await StartCheckoutAsync(admin, PlanEntitlementCatalog.Pro);
        var session = System.Web.HttpUtility.ParseQueryString(new Uri(url).Query)["session"]!;

        // Flip one character of the sealed body.
        var tampered = (session[0] == 'a' ? 'b' : 'a') + session[1..];

        var response = await host.CreateClient().GetAsync(
            $"/v1/billing/simulator/checkout?session={Uri.EscapeDataString(tampered)}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// Cancelling goes back empty-handed — the flow's other ending, and the one a stub forgets.
    /// </summary>
    [Fact]
    public async Task Cancelling_leaves_the_tenant_on_the_free_tier()
    {
        using var host = Simulated();
        var (tenant, user, _) = await SeedTenantAsync(PlanEntitlementCatalog.Free);
        var admin = Authed(host, tenant, user, Roles.Admin, AuthScopes.ScanWrite, AuthScopes.ScanRead);

        var url = await StartCheckoutAsync(admin, PlanEntitlementCatalog.Pro);
        var session = System.Web.HttpUtility.ParseQueryString(new Uri(url).Query)["session"]!;

        // Not following the redirect: where it points is the assertion, and the console origin it
        // points at is not a thing this test host serves.
        var cancelled = await host
            .CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false })
            .PostAsync(
            "/v1/billing/simulator/checkout/cancel",
            new FormUrlEncodedContent([new KeyValuePair<string, string>("session", session)]));

        Assert.Equal(HttpStatusCode.Redirect, cancelled.StatusCode);
        Assert.Contains("checkout=cancelled", cancelled.Headers.Location!.ToString());

        var after = await BodyAsync(await admin.GetAsync("/v1/billing/subscription"));
        Assert.Equal("none", after.GetProperty("data").GetProperty("status").GetString());
    }

    /// <summary>
    /// The simulator routes are only reachable when the simulated processor is the one in force.
    /// A deployment that moves to Stripe must not leave behind an endpoint that mints its own
    /// subscription events.
    /// </summary>
    [Fact]
    public async Task The_simulator_is_not_reachable_when_it_is_not_the_provider()
    {
        // Provider cleared: with no Stripe credentials either, that resolves to None. The
        // committed appsettings.json asks for Simulated, so this has to be said explicitly rather
        // than left to the default.
        using var host = _factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Billing:Provider"] = "",
                })));

        using var client = host.CreateClient();

        var response = await client.GetAsync("/v1/billing/simulator/checkout?session=anything");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>Starting a subscription is still an admin action, simulated or not.</summary>
    [Fact]
    public async Task An_analyst_cannot_start_a_simulated_checkout()
    {
        using var host = Simulated();
        var (tenant, user, _) = await SeedTenantAsync(PlanEntitlementCatalog.Free);
        var analyst = Authed(host, tenant, user, Roles.Analyst, AuthScopes.ScanWrite);

        var response = await analyst.PostAsJsonAsync("/v1/billing/checkout", new
        {
            planId = PlanEntitlementCatalog.Pro,
            period = "Monthly",
            quantity = 1,
            successUrl = $"{Origin}/billing?checkout=success",
            cancelUrl = $"{Origin}/billing?checkout=cancelled",
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>An off-origin return URL is refused before any session is minted.</summary>
    [Fact]
    public async Task A_return_url_outside_the_allowlist_is_refused()
    {
        using var host = Simulated();
        var (tenant, user, _) = await SeedTenantAsync(PlanEntitlementCatalog.Free);
        var admin = Authed(host, tenant, user, Roles.Admin, AuthScopes.ScanWrite);

        var response = await admin.PostAsJsonAsync("/v1/billing/checkout", new
        {
            planId = PlanEntitlementCatalog.Pro,
            period = "Monthly",
            quantity = 1,
            // Starts with the allowed origin, and is a different host.
            successUrl = "https://console.sentinelai.test.evil.example/billing",
            cancelUrl = $"{Origin}/billing",
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---- helpers ------------------------------------------------------------------------------

    private static async Task CompleteAsync(WebApplicationFactory<Program> host, string checkoutUrl)
    {
        var session = System.Web.HttpUtility.ParseQueryString(new Uri(checkoutUrl).Query)["session"]!;

        var paid = await host.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false })
            .PostAsync(
                "/v1/billing/simulator/checkout/complete",
                new FormUrlEncodedContent([new KeyValuePair<string, string>("session", session)]));

        Assert.Equal(HttpStatusCode.Redirect, paid.StatusCode);
    }

    private static async Task<HttpResponseMessage> SubmitAsync(HttpClient client, Guid projectId, string sha)
    {
        var metadata =
            $$"""
            {"project_id":"{{projectId}}","commit_sha":"{{sha}}","runner_secret_scan":"passed"}
            """;

        var bytes = TarGzTestHelper.Build(new Dictionary<string, string>
        {
            ["metadata.json"] = metadata,
            ["findings/osv.sarif"] = "{}",
        }).ToArray();

        var content = new MultipartFormDataContent { { new StringContent(metadata), "metadata" } };
        var file = new ByteArrayContent(bytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/gzip");
        content.Add(file, "bundle", "bundle.tar.gz");

        return await client.PostAsync("/v1/scans", content);
    }
}

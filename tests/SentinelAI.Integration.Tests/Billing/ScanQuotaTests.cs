using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Auth;
using SentinelAI.Integration.Tests.Scan;

namespace SentinelAI.Integration.Tests.Billing;

/// <summary>
/// The daily scan allowance, end to end through the real host.
/// </summary>
/// <remarks>
/// <para>
/// This is the suite that runs with <see cref="ScanApiFactory.RealEntitlements"/> on, so the tier
/// is read from <c>Tenant.PlanTier</c> and the meter is the real table. Every other suite runs with
/// entitlements stubbed — see the note in <c>ScanApiFactory</c> for why.
/// </para>
/// <para>
/// Its own host, not the shared class fixture, because the meter is per tenant per day and a
/// counter left behind by a neighbouring suite would make the assertions depend on what ran first.
/// </para>
/// </remarks>
public class ScanQuotaTests : IDisposable
{
    private readonly ScanApiFactory _factory = new() { RealEntitlements = true };

    public void Dispose()
    {
        _factory.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>A tenant on a named plan, with a project ready to scan.</summary>
    private async Task<(Guid Tenant, Guid Project)> SeedTenantAsync(string planTier)
    {
        var tenantId = Guid.NewGuid();
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

            db.Projects.Add(new Project
            {
                Id = projectId,
                TenantId = tenantId,
                RepoUrl = $"https://example.test/repo/{projectId}",
                DefaultBranch = "main",
            });
        });

        return (tenantId, projectId);
    }

    private HttpClient Client(Guid tenantId, params string[] scopes)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", TestJwt.Create(tenantId, userId: null, role: null, scopes: scopes));
        return client;
    }

    private static string Metadata(Guid projectId, string commitSha) =>
        $$"""
        {"project_id":"{{projectId}}","commit_sha":"{{commitSha}}","runner_secret_scan":"passed"}
        """;

    private static MultipartFormDataContent Bundle(Guid projectId, string commitSha)
    {
        var metadata = Metadata(projectId, commitSha);

        var bytes = TarGzTestHelper.Build(new Dictionary<string, string>
        {
            ["metadata.json"] = metadata,
            ["findings/osv.sarif"] = "{}",
        }).ToArray();

        var content = new MultipartFormDataContent { { new StringContent(metadata), "metadata" } };
        var file = new ByteArrayContent(bytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/gzip");
        content.Add(file, "bundle", "bundle.tar.gz");

        return content;
    }

    private async Task<HttpResponseMessage> SubmitAsync(HttpClient client, Guid projectId, string sha) =>
        await client.PostAsync("/v1/scans", Bundle(projectId, sha));

    // ---- the headline behaviour ------------------------------------------------------------

    /// <summary>
    /// The free tier's whole promise: two scans a day, and the third is refused rather than
    /// quietly queued.
    /// </summary>
    [Fact]
    public async Task The_free_plan_allows_two_scans_a_day_and_refuses_the_third()
    {
        var (tenant, project) = await SeedTenantAsync(PlanEntitlementCatalog.Free);
        var client = Client(tenant, AuthScopes.ScanWrite);

        Assert.Equal(HttpStatusCode.Accepted, (await SubmitAsync(client, project, "sha1")).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await SubmitAsync(client, project, "sha2")).StatusCode);

        var third = await SubmitAsync(client, project, "sha3");

        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
    }

    /// <summary>
    /// A 429 that does not say when to come back is one a CI runner will retry in a tight loop.
    /// </summary>
    [Fact]
    public async Task A_refusal_carries_retry_after_and_says_which_plan_refused_it()
    {
        var (tenant, project) = await SeedTenantAsync(PlanEntitlementCatalog.Free);
        var client = Client(tenant, AuthScopes.ScanWrite);

        await SubmitAsync(client, project, "sha1");
        await SubmitAsync(client, project, "sha2");
        var refused = await SubmitAsync(client, project, "sha3");

        var retryAfter = Assert.Single(refused.Headers.GetValues("Retry-After"));
        Assert.True(int.Parse(retryAfter) > 0, "Retry-After must be a positive number of seconds");

        using var body = JsonDocument.Parse(await refused.Content.ReadAsStringAsync());
        var message = body.RootElement.GetProperty("message").GetString();

        // The customer has to be able to act on this, which means knowing what the ceiling was
        // and that a plan is what set it.
        Assert.Contains(PlanEntitlementCatalog.Free, message);
        Assert.Contains("2 scans per day", message);
    }

    [Fact]
    public async Task A_paid_plan_is_not_refused_at_the_free_limit()
    {
        var (tenant, project) = await SeedTenantAsync(PlanEntitlementCatalog.Pro);
        var client = Client(tenant, AuthScopes.ScanWrite);

        foreach (var sha in new[] { "sha1", "sha2", "sha3", "sha4", "sha5" })
            Assert.Equal(HttpStatusCode.Accepted, (await SubmitAsync(client, project, sha)).StatusCode);
    }

    /// <summary>
    /// One tenant spending its allowance must not spend anyone else's — the meter is keyed on the
    /// tenant from the token, and this is what proves it rather than assuming it.
    /// </summary>
    [Fact]
    public async Task One_tenants_usage_does_not_count_against_another()
    {
        var (first, firstProject) = await SeedTenantAsync(PlanEntitlementCatalog.Free);
        var (second, secondProject) = await SeedTenantAsync(PlanEntitlementCatalog.Free);

        var firstClient = Client(first, AuthScopes.ScanWrite);
        await SubmitAsync(firstClient, firstProject, "sha1");
        await SubmitAsync(firstClient, firstProject, "sha2");
        Assert.Equal(
            HttpStatusCode.TooManyRequests,
            (await SubmitAsync(firstClient, firstProject, "sha3")).StatusCode);

        var secondClient = Client(second, AuthScopes.ScanWrite);
        Assert.Equal(
            HttpStatusCode.Accepted,
            (await SubmitAsync(secondClient, secondProject, "sha1")).StatusCode);
    }

    // ---- what must not spend quota ----------------------------------------------------------

    /// <summary>
    /// The reason the behavior is registered after <c>ValidationBehavior</c>. Reversed, a client
    /// sending garbage would burn a customer's allowance on requests that never reached a handler.
    /// </summary>
    [Fact]
    public async Task A_rejected_submission_does_not_spend_the_allowance()
    {
        var (tenant, project) = await SeedTenantAsync(PlanEntitlementCatalog.Free);
        var client = Client(tenant, AuthScopes.ScanWrite);

        // Malformed metadata: refused before the handler, and must cost nothing.
        var broken = new MultipartFormDataContent { { new StringContent("not json"), "metadata" } };
        var file = new ByteArrayContent([1, 2, 3]);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/gzip");
        broken.Add(file, "bundle", "bundle.tar.gz");

        var rejected = await client.PostAsync("/v1/scans", broken);
        Assert.NotEqual(HttpStatusCode.Accepted, rejected.StatusCode);
        Assert.NotEqual(HttpStatusCode.TooManyRequests, rejected.StatusCode);

        // The full allowance is still there.
        Assert.Equal(HttpStatusCode.Accepted, (await SubmitAsync(client, project, "sha1")).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await SubmitAsync(client, project, "sha2")).StatusCode);
    }

    /// <summary>
    /// Authorization comes before metering. A token that may not submit has to be told that, not
    /// told it is over a limit — and must not be charged for the attempt.
    /// </summary>
    [Fact]
    public async Task A_caller_without_scan_write_is_forbidden_rather_than_rate_limited()
    {
        var (tenant, project) = await SeedTenantAsync(PlanEntitlementCatalog.Free);

        var unscoped = Client(tenant, AuthScopes.ScanRead);
        var refused = await SubmitAsync(unscoped, project, "sha1");

        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);

        // And nothing was spent: the full allowance survives.
        var allowed = Client(tenant, AuthScopes.ScanWrite);
        Assert.Equal(HttpStatusCode.Accepted, (await SubmitAsync(allowed, project, "sha1")).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await SubmitAsync(allowed, project, "sha2")).StatusCode);
    }

    [Fact]
    public async Task An_anonymous_submission_is_unauthorized_rather_than_rate_limited()
    {
        var (_, project) = await SeedTenantAsync(PlanEntitlementCatalog.Free);

        var response = await _factory.CreateClient().PostAsync("/v1/scans", Bundle(project, "sha1"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// An unlimited plan never touches the meter — asserted by spending well past every finite
    /// tier's ceiling.
    /// </summary>
    [Fact]
    public async Task An_unlimited_plan_is_never_metered()
    {
        var (tenant, project) = await SeedTenantAsync(PlanEntitlementCatalog.Enterprise);
        var client = Client(tenant, AuthScopes.ScanWrite);

        for (var i = 0; i < 6; i++)
            Assert.Equal(HttpStatusCode.Accepted, (await SubmitAsync(client, project, $"sha{i}")).StatusCode);
    }

    /// <summary>
    /// A tenant whose plan string means nothing to us is metered as free, not as unlimited. The
    /// direction matters: a retired plan id or a subscription created by hand in the Stripe
    /// dashboard must fail to the least privilege.
    /// </summary>
    [Fact]
    public async Task An_unknown_plan_is_metered_as_the_free_tier()
    {
        var (tenant, project) = await SeedTenantAsync("plan-that-does-not-exist");
        var client = Client(tenant, AuthScopes.ScanWrite);

        await SubmitAsync(client, project, "sha1");
        await SubmitAsync(client, project, "sha2");

        Assert.Equal(
            HttpStatusCode.TooManyRequests,
            (await SubmitAsync(client, project, "sha3")).StatusCode);
    }
}

using System.Net;
using System.Net.Http.Headers;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Auth;

/// <summary>
/// SEC-32's checklist, proven through the real HTTP pipeline — auth middleware,
/// <c>[Authorize(Roles=...)]</c>, and the EF tenant query filter — rather than by calling a
/// handler directly with a hand-built <c>ICallerContext</c> (which is how SEC-13's tests
/// work, and which can't prove 401/403 exist at all).
/// </summary>
public class AuthAndTenantIsolationTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;

    public AuthAndTenantIsolationTests(ScanApiFactory factory) => _factory = factory;

    /// <summary>A job needs a real Project row too — ScanJobRepository still joins through
    /// Project.TenantId, on top of the new denormalized ScanJob.TenantId column.</summary>
    private async Task<ScanJob> SeedJobAsync(Guid tenantId)
    {
        var project = new Project { Id = Guid.NewGuid(), TenantId = tenantId, RepoUrl = "https://example.com/repo.git" };
        var job = new ScanJob
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ProjectId = project.Id,
            CommitSha = "abc123",
            Status = ScanStatus.Queued,
            Stage = ScanStage.Received,
            CorpusVersion = "test",
            StartedAt = DateTime.UtcNow,
        };

        await _factory.SeedAsync(db =>
        {
            db.Projects.Add(project);
            db.ScanJobs.Add(job);
        });

        return job;
    }

    private HttpClient AuthorizedClient(string token)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    // ---- Guarantee 1: no token -> 401 ------------------------------------------------

    [Fact]
    public async Task No_token_is_rejected_with_401()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync($"/v1/scans/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ---- Guarantee 2: role restrictions -----------------------------------------------

    [Fact]
    public async Task Viewer_role_cannot_purge_a_bundle()
    {
        var tenantId = Guid.NewGuid();
        var job = await SeedJobAsync(tenantId);
        var client = AuthorizedClient(TestJwt.Create(tenantId, role: Roles.Viewer));

        var response = await client.PostAsync($"/v1/scans/{job.Id}/purge", null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Admin_role_can_purge_a_bundle_within_their_own_tenant()
    {
        var tenantId = Guid.NewGuid();
        var job = await SeedJobAsync(tenantId);
        var client = AuthorizedClient(TestJwt.Create(tenantId, role: Roles.Admin));

        var response = await client.PostAsync($"/v1/scans/{job.Id}/purge", null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ---- Guarantee 3: tenant isolation -------------------------------------------------

    [Fact]
    public async Task Same_tenant_can_read_its_own_scan_job()
    {
        var tenantId = Guid.NewGuid();
        var job = await SeedJobAsync(tenantId);
        var client = AuthorizedClient(TestJwt.Create(tenantId));

        var response = await client.GetAsync($"/v1/scans/{job.Id}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Tenant_a_reading_tenant_bs_scan_job_returns_nothing()
    {
        var tenantB = Guid.NewGuid();
        var jobB = await SeedJobAsync(tenantB);
        var client = AuthorizedClient(TestJwt.Create(Guid.NewGuid())); // tenant A, unrelated

        var response = await client.GetAsync($"/v1/scans/{jobB.Id}");

        // Not 403 - a 403 would confirm jobB exists. It looks identical to "not found".
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ---- Guarantee 4: the machine token can only submit scans -------------------------

    [Fact]
    public async Task Machine_token_scoped_to_scan_write_cannot_purge_a_bundle()
    {
        var tenantId = Guid.NewGuid();
        var job = await SeedJobAsync(tenantId);
        // No role claim at all - exactly what the Action's machine token carries.
        var client = AuthorizedClient(TestJwt.Create(tenantId, scopes: [AuthScopes.ScanWrite]));

        var response = await client.PostAsync($"/v1/scans/{job.Id}/purge", null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}

using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.ReadApi;

/// <summary>
/// <c>GET /v1/scans/{id}/audit-integrity</c> — the operator surface.
/// </summary>
/// <remarks>
/// Two properties are worth more than the shape of the payload: it is admin-only, and it is not an
/// existence oracle. The second is the subtle one — a role gate applied before the tenant check
/// would let any admin learn which scan ids exist in other tenants by the difference between 403
/// and 404.
/// </remarks>
public class AuditIntegrityEndpointTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;
    private readonly ReadApiFixture _fixture;

    public AuditIntegrityEndpointTests(ScanApiFactory factory)
    {
        _factory = factory;
        _fixture = new ReadApiFixture(factory);
        _fixture.SeedAsync().GetAwaiter().GetResult();
        SeedIntegrityAsync().GetAwaiter().GetResult();
    }

    private async Task SeedIntegrityAsync() =>
        await _factory.SeedAsync(db => db.ScanAuditIntegrities.Add(new ScanAuditIntegrity
        {
            Id = Guid.CreateVersion7(),
            TenantId = _fixture.TenantId,
            ScanJobId = _fixture.ScanJobId,
            Adjudicated = true,
            Outcome = "Converged",
            Rounds = 3,
            VerdictReadable = true,
            TerminatedByTurnCap = false,
            WeakestJoin = "Inferred",
            EdgeIntegrityWarnings = 1,
            EdgeIntegrityDetail = "hop 2 names two nodes with no edge between them",
            AbandonedReasoningWarnings = 0,
            RetrievalFindings = 3,
            RetrievalGrounded = 2,
            CoveragePercent = 66,
            ModesThatDidNotFire = "Capec",
            CandidateChains = 4,
            ChainsAdjudicated = 1,
            CorpusVersion = "2026-07-15",
            HarnessVersion = 1,
            CreatedAt = DateTime.UtcNow,
        }));

    private HttpClient Client(Guid tenantId, string role) =>
        Authed(tenantId, role, AuthScopes.ScanRead, AuthScopes.ReportRead);

    private HttpClient Authed(Guid tenantId, string role, params string[] scopes)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", TestJwt.Create(tenantId, userId: Guid.CreateVersion7(), role: role, scopes: scopes));
        return client;
    }

    private string Url(Guid? scanJobId = null) =>
        $"/v1/scans/{scanJobId ?? _fixture.ScanJobId}/audit-integrity";

    [Fact]
    public async Task An_admin_reads_what_the_checks_found()
    {
        var response = await Client(_fixture.TenantId, Roles.Admin).GetAsync(Url());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await ReadApiFixture.JsonAsync(response);

        Assert.Equal("converged", json.GetProperty("outcome").GetString());
        Assert.Equal(3, json.GetProperty("rounds").GetInt32());
        Assert.True(json.GetProperty("verdict_readable").GetBoolean());
        Assert.Equal(66, json.GetProperty("coverage_percent").GetInt32());

        // The number the whole record exists for.
        Assert.Equal(1, json.GetProperty("edge_integrity_warnings").GetInt32());
        Assert.Contains(
            "no edge between them",
            json.GetProperty("edge_integrity_detail").EnumerateArray().First().GetString());
    }

    /// <summary>
    /// "1 adjudicated of 4" is the fact this record exists to make visible: the debate reasons over
    /// the single strongest candidate and the rest stay candidates, which is true and otherwise
    /// invisible unless somebody counts.
    /// </summary>
    [Fact]
    public async Task It_reports_how_many_chains_were_actually_adjudicated()
    {
        var json = await ReadApiFixture.JsonAsync(
            await Client(_fixture.TenantId, Roles.Admin).GetAsync(Url()));

        Assert.Equal(4, json.GetProperty("candidate_chains").GetInt32());
        Assert.Equal(1, json.GetProperty("chains_adjudicated").GetInt32());
    }

    [Theory]
    [InlineData("analyst")]
    [InlineData("viewer")]
    public async Task A_non_admin_is_refused(string role)
    {
        var response = await Client(_fixture.TenantId, role).GetAsync(Url());

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// The existence-oracle probe. Another tenant's admin gets 404 — the same answer they get for a
    /// scan id that was never real — so the endpoint tells them nothing either way.
    /// </summary>
    [Fact]
    public async Task Another_tenants_admin_gets_404_and_not_403()
    {
        var stranger = Authed(Guid.NewGuid(), Roles.Admin, AuthScopes.ScanRead);

        var real = await stranger.GetAsync(Url());
        var invented = await stranger.GetAsync(Url(Guid.CreateVersion7()));

        Assert.Equal(HttpStatusCode.NotFound, real.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, invented.StatusCode);
    }

    /// <summary>
    /// A scan that has not been audited yet has no record, and that is a 404 rather than an empty
    /// object — "not adjudicated yet" and "adjudicated, nothing to report" are different answers.
    /// </summary>
    [Fact]
    public async Task A_scan_with_no_record_yet_is_a_404()
    {
        var jobId = Guid.CreateVersion7();

        await _factory.SeedAsync(db => db.ScanJobs.Add(new ScanJob
        {
            Id = jobId,
            TenantId = _fixture.TenantId,
            ProjectId = _fixture.ProjectId,
            PrRef = "pr/none",
            CommitSha = "nosuchaudit",
            CorpusVersion = "2026-07-15",
            StartedAt = DateTime.UtcNow,
        }));

        var response = await Client(_fixture.TenantId, Roles.Admin).GetAsync(Url(jobId));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task An_anonymous_caller_is_refused()
    {
        var response = await _factory.CreateClient().GetAsync(Url());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}

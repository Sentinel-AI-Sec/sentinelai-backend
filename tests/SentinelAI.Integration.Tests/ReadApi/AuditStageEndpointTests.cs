using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.ReadApi;

/// <summary>
/// <c>POST /v1/scans/{id}/audit</c> — the stage runner that makes a report exist (SEC-40 Route B).
/// </summary>
/// <remarks>
/// <para>
/// Without this endpoint the report stage was reachable only from tests, so <c>GET
/// /v1/reports/{id}</c> would answer "not found" forever however correct it was. These tests
/// close that loop: run the audit, then read the report back through the read API.
/// </para>
/// <para>
/// They run against the default <c>Scripted</c> provider, so the debate is offline, instant and
/// identical every time — no API key, no network, no token spend.
/// </para>
/// </remarks>
public class AuditStageEndpointTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;
    private readonly Guid _tenantId = Guid.NewGuid();

    public AuditStageEndpointTests(ScanApiFactory factory) => _factory = factory;

    private HttpClient ClientWith(params string[] scopes)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", TestJwt.Create(_tenantId, userId: Guid.NewGuid(), role: Roles.Analyst, scopes: scopes));
        return client;
    }

    /// <summary>Seeds a scan left exactly as the graph stage leaves one: findings and nodes.</summary>
    private async Task<Guid> SeedScannedJobAsync(bool retainReport)
    {
        var projectId = Guid.CreateVersion7();
        var jobId = Guid.CreateVersion7();

        await _factory.SeedAsync(db =>
        {
            db.Projects.Add(new Project
            {
                Id = projectId, TenantId = _tenantId,
                RepoUrl = "https://example.test/repo", DefaultBranch = "main",
            });

            db.ScanJobs.Add(new ScanJob
            {
                Id = jobId, TenantId = _tenantId, ProjectId = projectId,
                PrRef = "pr/1", CommitSha = "abc123", Status = ScanStatus.Running,
                CorpusVersion = "2026-07-15", StartedAt = DateTime.UtcNow,
                Stage = ScanStage.Graph, RetainReport = retainReport, BundlePurged = false,
            });

            db.Findings.Add(new Finding
            {
                Id = Guid.CreateVersion7(), TenantId = _tenantId, ScanJobId = jobId,
                SourceTool = "roslyn", Layer = Layer.Code, Severity = 4,
                CweId = "CWE-502", NodeRef = "code:orderservice.deserialize",
                Message = "Unsafe deserialization of untrusted data.",
            });

            db.GraphNodes.Add(new GraphNode
            {
                Id = Guid.CreateVersion7(), TenantId = _tenantId, ScanJobId = jobId,
                NodeKey = "code:orderservice.deserialize",
                NodeType = NodeType.Code, Layer = Layer.Code, IsHot = true,
            });
        });

        return jobId;
    }

    [Fact]
    public async Task Running_the_audit_produces_a_readable_report_when_retention_was_opted_into()
    {
        var jobId = await SeedScannedJobAsync(retainReport: true);
        var client = ClientWith(AuthScopes.ScanWrite, AuthScopes.ReportRead);

        var run = await client.PostAsync($"/v1/scans/{jobId}/audit", null);
        Assert.Equal(HttpStatusCode.OK, run.StatusCode);

        var body = await ReadApiFixture.JsonAsync(run);
        var result = body.GetProperty("data");

        Assert.True(result.GetProperty("report_retained").GetBoolean());
        Assert.True(result.GetProperty("bundle_purged").GetBoolean());
        Assert.Equal("draft_audit", result.GetProperty("framing").GetString());

        // The whole point of Route B: the id it returns is fetchable through the read API.
        var reportId = result.GetProperty("report_id").GetString();
        Assert.NotNull(reportId);

        var read = await client.GetAsync($"/v1/reports/{reportId}");
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);

        var report = await ReadApiFixture.JsonAsync(read);
        Assert.Equal("draft_audit", report.GetProperty("framing").GetString());
        Assert.Equal(jobId.ToString(), report.GetProperty("scan_job_id").GetString());
    }

    [Fact]
    public async Task The_scan_itself_names_the_report_so_a_worker_driven_run_can_be_followed()
    {
        // Route B returns report_id from POST /audit, which is fine when a caller drove the
        // audit. SEC-46's worker drives it instead, and nothing receives that response — so
        // the id has to be reachable from the scan the Action already polls, or the report
        // exists and no caller can find it. That is exactly what happened on the first live
        // fixture run: the audit completed, the report was retained, and the id had to be
        // read out of SQL by hand.
        var jobId = await SeedScannedJobAsync(retainReport: true);
        var client = ClientWith(AuthScopes.ScanWrite, AuthScopes.ReportRead);

        var before = await ReadApiFixture.JsonAsync(await client.GetAsync($"/v1/scans/{jobId}"));
        Assert.Equal(
            JsonValueKind.Null,
            before.GetProperty("data").GetProperty("reportId").ValueKind);

        await client.PostAsync($"/v1/scans/{jobId}/audit", null);

        var after = await ReadApiFixture.JsonAsync(await client.GetAsync($"/v1/scans/{jobId}"));
        var reportId = after.GetProperty("data").GetProperty("reportId").GetString();
        Assert.False(string.IsNullOrWhiteSpace(reportId));

        // Reachable, not merely present: the id the scan hands back fetches the report.
        var read = await client.GetAsync($"/v1/reports/{reportId}");
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        Assert.Equal(
            jobId.ToString(),
            (await ReadApiFixture.JsonAsync(read)).GetProperty("scan_job_id").GetString());
    }

    [Fact]
    public async Task Without_the_opt_in_the_audit_still_runs_but_nothing_is_kept()
    {
        // SEC-35's second rule, visible through SEC-40's own endpoint. The caller gets their
        // audit in the response; we simply do not write it down.
        var jobId = await SeedScannedJobAsync(retainReport: false);
        var client = ClientWith(AuthScopes.ScanWrite, AuthScopes.ReportRead);

        var run = await client.PostAsync($"/v1/scans/{jobId}/audit", null);
        Assert.Equal(HttpStatusCode.OK, run.StatusCode);

        var result = (await ReadApiFixture.JsonAsync(run)).GetProperty("data");

        Assert.False(result.GetProperty("report_retained").GetBoolean());
        Assert.Equal(JsonValueKind.Null, result.GetProperty("report_id").ValueKind);

        // The audit itself was still produced and returned.
        Assert.False(string.IsNullOrWhiteSpace(result.GetProperty("summary").GetString()));

        await _factory.SeedAsync(db =>
            Assert.Empty(db.Reports.IgnoreQueryFilters().Where(r => r.ScanJobId == jobId).ToList()));
    }

    [Fact]
    public async Task The_bundle_is_purged_either_way()
    {
        // Opting into report retention is not opting into keeping the uploaded bundle.
        var jobId = await SeedScannedJobAsync(retainReport: true);

        await ClientWith(AuthScopes.ScanWrite).PostAsync($"/v1/scans/{jobId}/audit", null);

        await _factory.SeedAsync(db =>
            Assert.True(db.ScanJobs.IgnoreQueryFilters().Single(j => j.Id == jobId).BundlePurged));
    }

    [Fact]
    public async Task A_job_with_no_findings_is_told_to_run_the_graph_stage_first()
    {
        // Auditing nothing would produce a confident report about an empty system — which
        // reads exactly like a clean scan.
        var projectId = Guid.CreateVersion7();
        var jobId = Guid.CreateVersion7();

        await _factory.SeedAsync(db =>
        {
            db.Projects.Add(new Project
            {
                Id = projectId, TenantId = _tenantId,
                RepoUrl = "https://example.test/repo", DefaultBranch = "main",
            });
            db.ScanJobs.Add(new ScanJob
            {
                Id = jobId, TenantId = _tenantId, ProjectId = projectId,
                PrRef = "pr/1", CommitSha = "abc", Status = ScanStatus.Queued,
                CorpusVersion = "v1", StartedAt = DateTime.UtcNow, Stage = ScanStage.Received,
            });
        });

        var response = await ClientWith(AuthScopes.ScanWrite).PostAsync($"/v1/scans/{jobId}/audit", null);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task Running_an_audit_requires_the_scan_write_scope()
    {
        // It writes a report and deletes a bundle — a read scope must not be enough.
        var jobId = await SeedScannedJobAsync(retainReport: true);

        var response = await ClientWith(AuthScopes.ScanRead).PostAsync($"/v1/scans/{jobId}/audit", null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Another_tenants_job_cannot_be_audited()
    {
        var jobId = await SeedScannedJobAsync(retainReport: true);

        var foreign = _factory.CreateClient();
        foreign.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(),
                role: Roles.Analyst, scopes: [AuthScopes.ScanWrite]));

        var response = await foreign.PostAsync($"/v1/scans/{jobId}/audit", null);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}

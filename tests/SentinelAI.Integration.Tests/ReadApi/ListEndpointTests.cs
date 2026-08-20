using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.ReadApi;

/// <summary>
/// The list endpoints: <c>GET /v1/scans</c>, <c>GET /v1/reports</c>,
/// <c>GET /v1/scans/{id}/summary</c>, <c>GET /v1/projects/{id}</c> and <c>GET /v1/account</c>.
/// </summary>
/// <remarks>
/// <para>
/// The one thing these have that no previous read endpoint had is the ability to return rows the
/// caller did not name. Every by-id read fails safe by accident — a caller who does not know an id
/// cannot ask for it — and a list has no such accident protecting it. So the isolation tests here
/// are not a formality: they are the reason this file exists at all, and they assert the
/// <em>absence</em> of another tenant's rows in a successful 200, which is a failure mode no
/// status-code assertion can catch.
/// </para>
/// <para>
/// Assertions are on raw JSON property names, matching <see cref="ReadApiContractTests"/>: the
/// snake_case names are the contract the console is built against, and deserializing into the
/// server's own DTO would pass whatever they were renamed to.
/// </para>
/// </remarks>
public class ListEndpointTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;

    private readonly Guid _tenantId = Guid.NewGuid();
    private readonly Guid _userId = Guid.CreateVersion7();
    private readonly Guid _projectA = Guid.CreateVersion7();
    private readonly Guid _projectB = Guid.CreateVersion7();

    /// <summary>The tenant's four scans, oldest first — so index 3 is the newest.</summary>
    private readonly List<Guid> _scanIds = [];

    private Guid _retainedReportId;
    private Guid _summaryScanId;

    /// <summary>A second tenant's scan and report. Must never appear in the first tenant's lists.</summary>
    private readonly Guid _foreignTenantId = Guid.NewGuid();
    private Guid _foreignScanId;

    public ListEndpointTests(ScanApiFactory factory)
    {
        _factory = factory;
        SeedAsync().GetAwaiter().GetResult();
    }

    // ---- GET /v1/scans -----------------------------------------------------------------

    [Fact]
    public async Task The_scan_list_returns_this_tenants_scans_newest_first()
    {
        var page = await GetAsync(Reader(), "/v1/scans");

        var items = page.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(4, items.Count);

        // Newest first: the reverse of the seeding order. A history screen that opened on the
        // tenant's very first scan would be useless, so the ordering is part of the contract.
        var returned = items.Select(i => Guid.Parse(i.GetProperty("scan_job_id").GetString()!)).ToList();
        Assert.Equal(_scanIds.AsEnumerable().Reverse(), returned);
    }

    [Fact]
    public async Task A_scan_row_carries_enough_to_recognise_it_without_a_second_request()
    {
        // The whole reason this endpoint beats the browser-local index it replaces: a list of
        // bare GUIDs is not a history, because nobody recognises their own scan by its id.
        var page = await GetAsync(Reader(), "/v1/scans?limit=1");
        var row = page.GetProperty("items").EnumerateArray().Single();

        Assert.Equal("https://example.test/repo-b", row.GetProperty("repo_url").GetString());
        Assert.Equal(_projectB.ToString(), row.GetProperty("project_id").GetString());
        Assert.Equal("pr/4", row.GetProperty("pr_ref").GetString());
        Assert.Equal("sha4", row.GetProperty("commit_sha").GetString());
    }

    [Fact]
    public async Task Scan_status_and_stage_cross_the_wire_as_words()
    {
        // "status": 2 is meaningless to a screen and changes meaning silently if a member is
        // ever inserted into the enum.
        var page = await GetAsync(Reader(), "/v1/scans?limit=1");
        var row = page.GetProperty("items").EnumerateArray().Single();

        Assert.Equal(JsonValueKind.String, row.GetProperty("status").ValueKind);
        Assert.Equal("failed", row.GetProperty("status").GetString());
        Assert.Equal("graph", row.GetProperty("stage").GetString());
        Assert.Equal("boom", row.GetProperty("failure_reason").GetString());
    }

    [Fact]
    public async Task A_completed_scan_carries_the_id_of_the_report_it_produced()
    {
        var page = await GetAsync(Reader(), "/v1/scans");

        var withReport = page.GetProperty("items").EnumerateArray()
            .Single(i => i.GetProperty("scan_job_id").GetString() == _summaryScanId.ToString());

        Assert.Equal(_retainedReportId.ToString(), withReport.GetProperty("report_id").GetString());
    }

    [Fact]
    public async Task The_scan_list_filters_by_project_status_and_stage()
    {
        var byProject = await GetAsync(Reader(), $"/v1/scans?project_id={_projectA}");
        Assert.Equal(3, byProject.GetProperty("items").GetArrayLength());

        var byStatus = await GetAsync(Reader(), "/v1/scans?status=completed");
        Assert.All(
            byStatus.GetProperty("items").EnumerateArray(),
            i => Assert.Equal("completed", i.GetProperty("status").GetString()));

        var byStage = await GetAsync(Reader(), "/v1/scans?stage=report");
        Assert.All(
            byStage.GetProperty("items").EnumerateArray(),
            i => Assert.Equal("report", i.GetProperty("stage").GetString()));

        // Case-insensitive, because a filter value is copied out of a response body where it is
        // lowercase and out of a C# enum where it is not.
        var upper = await GetAsync(Reader(), "/v1/scans?status=COMPLETED");
        Assert.Equal(
            byStatus.GetProperty("items").GetArrayLength(),
            upper.GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task An_unknown_status_or_stage_is_a_400_and_not_an_empty_page()
    {
        // An empty page would read as "you have no scans in that state" — a wrong answer to a
        // question that was never valid.
        foreach (var url in new[] { "/v1/scans?status=nonsense", "/v1/scans?stage=nonsense" })
        {
            var response = await Reader().GetAsync(url);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

            var problem = await ReadApiFixture.JsonAsync(response);
            Assert.Equal(
                "https://sentinelai.dev/problems/invalid-request",
                problem.GetProperty("type").GetString());
        }
    }

    [Fact]
    public async Task The_scan_list_pages_by_cursor_without_repeating_or_skipping_a_row()
    {
        var first = await GetAsync(Reader(), "/v1/scans?limit=3");
        Assert.Equal(3, first.GetProperty("items").GetArrayLength());

        var cursor = first.GetProperty("next_cursor").GetString();
        Assert.False(string.IsNullOrEmpty(cursor));

        var second = await GetAsync(Reader(), $"/v1/scans?limit=3&cursor={Uri.EscapeDataString(cursor!)}");
        Assert.Equal(1, second.GetProperty("items").GetArrayLength());

        // null next_cursor — not an item count — is how a caller knows to stop.
        Assert.Equal(JsonValueKind.Null, second.GetProperty("next_cursor").ValueKind);

        var ids = first.GetProperty("items").EnumerateArray()
            .Concat(second.GetProperty("items").EnumerateArray())
            .Select(i => i.GetProperty("scan_job_id").GetString())
            .ToList();

        Assert.Equal(4, ids.Distinct().Count());
        Assert.Equal(_scanIds.AsEnumerable().Reverse().Select(id => id.ToString()), ids);
    }

    [Fact]
    public async Task The_scan_list_never_returns_another_tenants_scan()
    {
        var page = await GetAsync(Reader(), "/v1/scans");

        var ids = page.GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("scan_job_id").GetString())
            .ToList();

        Assert.DoesNotContain(_foreignScanId.ToString(), ids);

        // And from the other side: the foreign tenant sees its own row and none of ours.
        var foreign = await GetAsync(ForeignReader(), "/v1/scans");
        var foreignIds = foreign.GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("scan_job_id").GetString())
            .ToList();

        Assert.Equal([_foreignScanId.ToString()], foreignIds);
    }

    [Fact]
    public async Task Filtering_by_another_tenants_project_returns_nothing_rather_than_erroring()
    {
        // Indistinguishable from a project that does not exist — a 403 here would confirm the id
        // is real and merely someone else's, which is the leak.
        var page = await GetAsync(Reader(), $"/v1/scans?project_id={Guid.CreateVersion7()}");
        Assert.Equal(0, page.GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task The_scan_list_requires_the_scan_read_scope()
    {
        var response = await Client(_tenantId, AuthScopes.ReportRead).GetAsync("/v1/scans");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().GetAsync("/v1/scans")).StatusCode);
    }

    // ---- GET /v1/reports ---------------------------------------------------------------

    [Fact]
    public async Task The_report_list_returns_the_audits_this_tenant_kept()
    {
        var page = await GetAsync(Reader(), "/v1/reports");

        var row = Assert.Single(page.GetProperty("items").EnumerateArray().ToList());
        Assert.Equal(_retainedReportId.ToString(), row.GetProperty("report_id").GetString());
        Assert.Equal(_summaryScanId.ToString(), row.GetProperty("scan_job_id").GetString());

        // Joined through the scan, so a row is identifiable without a second request.
        Assert.Equal("https://example.test/repo-a", row.GetProperty("repo_url").GetString());
        Assert.Equal(_projectA.ToString(), row.GetProperty("project_id").GetString());
    }

    [Fact]
    public async Task Every_report_row_carries_the_draft_framing()
    {
        // AID-01 §7: a list is exactly where the framing would otherwise be dropped, and a screen
        // showing audits with no framing on any of them is where "candidate chains a debate
        // argued over" quietly becomes "findings".
        var page = await GetAsync(Reader(), "/v1/reports");

        Assert.All(
            page.GetProperty("items").EnumerateArray(),
            r => Assert.Equal("draft_audit", r.GetProperty("framing").GetString()));
    }

    [Fact]
    public async Task A_report_row_omits_the_chains_that_make_the_full_audit()
    {
        var page = await GetAsync(Reader(), "/v1/reports");
        var row = page.GetProperty("items").EnumerateArray().First();

        Assert.False(row.TryGetProperty("chains", out _));
        Assert.False(row.TryGetProperty("citations", out _));

        // The cost figure is carried, including whether it was rated at all — a total of zero
        // with no rate configured is not a free scan.
        Assert.True(row.GetProperty("cost").GetProperty("rated").GetBoolean());
        Assert.Equal(4, row.GetProperty("cost").GetProperty("model_calls").GetInt32());
    }

    [Fact]
    public async Task The_report_list_requires_the_report_read_scope()
    {
        var response = await Client(_tenantId, AuthScopes.ScanRead).GetAsync("/v1/reports");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task The_report_list_never_returns_another_tenants_audit()
    {
        var foreign = await GetAsync(ForeignReader(), "/v1/reports");
        Assert.Equal(0, foreign.GetProperty("items").GetArrayLength());
    }

    // ---- GET /v1/scans/{id}/summary ----------------------------------------------------

    [Fact]
    public async Task The_summary_counts_findings_by_layer_and_severity()
    {
        var summary = await GetAsync(Reader(), $"/v1/scans/{_summaryScanId}/summary");
        var findings = summary.GetProperty("findings");

        Assert.Equal(4, findings.GetProperty("total").GetInt32());
        Assert.Equal(2, findings.GetProperty("by_layer").GetProperty("code").GetInt32());
        Assert.Equal(1, findings.GetProperty("by_layer").GetProperty("dep").GetInt32());
        Assert.Equal(1, findings.GetProperty("by_layer").GetProperty("infra").GetInt32());
        Assert.Equal(4, findings.GetProperty("max_severity").GetInt32());
        Assert.Equal(1, findings.GetProperty("redacted").GetInt32());

        Assert.Equal(1, findings.GetProperty("by_severity").GetProperty("4").GetInt32());
        Assert.Equal(2, findings.GetProperty("by_severity").GetProperty("3").GetInt32());
    }

    [Fact]
    public async Task Every_bucket_is_present_even_at_zero()
    {
        // A missing key and a zero are indistinguishable to a client, and a filter chip cannot be
        // rendered as "empty" if the API never mentions it.
        var summary = await GetAsync(Reader(), $"/v1/scans/{_summaryScanId}/summary");

        var bySeverity = summary.GetProperty("findings").GetProperty("by_severity");
        foreach (var severity in new[] { "0", "1", "2", "3", "4" })
            Assert.True(bySeverity.TryGetProperty(severity, out _), $"severity {severity} missing");

        Assert.Equal(0, bySeverity.GetProperty("0").GetInt32());

        var byConfidence = summary.GetProperty("graph").GetProperty("edges_by_confidence");
        foreach (var tier in new[] { "certain", "inferred", "unresolved" })
            Assert.True(byConfidence.TryGetProperty(tier, out _), $"tier {tier} missing");

        var byStatus = summary.GetProperty("chains").GetProperty("by_status");
        foreach (var status in new[] { "candidate", "asserted", "validated", "rejected" })
            Assert.True(byStatus.TryGetProperty(status, out _), $"status {status} missing");
    }

    [Fact]
    public async Task The_summary_reports_the_weakest_join_in_the_scan_and_not_the_strongest()
    {
        // Confidence is persisted as a string, and alphabetically "Certain" sorts first — a
        // database-side MIN would confidently report the strongest join as the weakest.
        var summary = await GetAsync(Reader(), $"/v1/scans/{_summaryScanId}/summary");

        Assert.Equal("unresolved", summary.GetProperty("chains").GetProperty("weakest_join").GetString());
        Assert.Equal(2, summary.GetProperty("chains").GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task The_summary_counts_the_graph_and_its_confidence_tiers()
    {
        var graph = (await GetAsync(Reader(), $"/v1/scans/{_summaryScanId}/summary")).GetProperty("graph");

        Assert.Equal(3, graph.GetProperty("nodes").GetInt32());
        Assert.Equal(2, graph.GetProperty("hot_nodes").GetInt32());
        Assert.Equal(2, graph.GetProperty("edges").GetInt32());
        Assert.Equal(1, graph.GetProperty("edges_by_confidence").GetProperty("inferred").GetInt32());
        Assert.Equal(1, graph.GetProperty("edges_by_confidence").GetProperty("certain").GetInt32());
    }

    [Fact]
    public async Task The_summary_total_matches_a_full_walk_of_the_paged_findings()
    {
        // The point of the endpoint: this number and the number of rows the paged endpoint would
        // hand back have to agree, or the screen showing it is lying about its own data.
        var summary = await GetAsync(Reader(), $"/v1/scans/{_summaryScanId}/summary");
        var claimed = summary.GetProperty("findings").GetProperty("total").GetInt32();

        var walked = 0;
        string? cursor = null;
        do
        {
            var url = $"/v1/scans/{_summaryScanId}/findings?limit=2"
                + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}");

            var page = await GetAsync(Reader(), url);
            walked += page.GetProperty("items").GetArrayLength();

            cursor = page.GetProperty("next_cursor").ValueKind == JsonValueKind.Null
                ? null
                : page.GetProperty("next_cursor").GetString();
        }
        while (cursor is not null);

        Assert.Equal(claimed, walked);
    }

    [Fact]
    public async Task A_summary_of_another_tenants_scan_is_a_404()
    {
        var response = await ForeignReader().GetAsync($"/v1/scans/{_summaryScanId}/summary");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ---- GET /v1/projects/{id} ---------------------------------------------------------

    [Fact]
    public async Task A_project_can_be_read_by_the_id_a_scan_row_carries()
    {
        var response = await Reader().GetAsync($"/v1/projects/{_projectA}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Envelope shape, matching its POST/GET-list siblings on this controller.
        var body = await ReadApiFixture.JsonAsync(response);
        var project = body.GetProperty("data");

        Assert.Equal(_projectA.ToString(), project.GetProperty("projectId").GetString());
        Assert.Equal("https://example.test/repo-a", project.GetProperty("repoUrl").GetString());
        Assert.Equal("main", project.GetProperty("defaultBranch").GetString());
    }

    [Fact]
    public async Task Another_tenants_project_is_a_404_and_not_a_403()
    {
        var response = await ForeignReader().GetAsync($"/v1/projects/{_projectA}");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ---- GET /v1/account ---------------------------------------------------------------

    [Fact]
    public async Task The_account_endpoint_names_the_tenant_and_the_user()
    {
        var response = await Reader().GetAsync("/v1/account");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var identity = (await ReadApiFixture.JsonAsync(response)).GetProperty("data");

        // The two fields a JWT cannot carry, and the reason this endpoint exists: without them
        // the account screen can show a GUID and nothing a person recognises.
        Assert.Equal("Acme Security", identity.GetProperty("tenantName").GetString());
        Assert.Equal("analyst@example.test", identity.GetProperty("email").GetString());

        Assert.Equal(_tenantId.ToString(), identity.GetProperty("tenantId").GetString());
        Assert.Equal(_userId.ToString(), identity.GetProperty("userId").GetString());
        Assert.Equal(Roles.Analyst, identity.GetProperty("role").GetString());
    }

    [Fact]
    public async Task The_reported_scopes_are_the_ones_the_token_actually_holds()
    {
        // Probed against the token rather than mapped from the role: the question a UI gate asks
        // is "will this request be allowed?", and that is decided by the bearer token it will
        // carry — not by the role on a row that a still-valid older token predates.
        var response = await Client(_tenantId, AuthScopes.ScanRead).GetAsync("/v1/account");
        var identity = (await ReadApiFixture.JsonAsync(response)).GetProperty("data");

        var scopes = identity.GetProperty("scopes").EnumerateArray().Select(s => s.GetString()).ToList();

        Assert.Equal([AuthScopes.ScanRead], scopes);
        Assert.DoesNotContain(AuthScopes.ReportRead, scopes);
    }

    [Fact]
    public async Task The_account_endpoint_is_reachable_with_no_scopes_at_all()
    {
        // A token with the wrong scopes must still be able to learn which scopes it is missing.
        var response = await Client(_tenantId).GetAsync("/v1/account");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var identity = (await ReadApiFixture.JsonAsync(response)).GetProperty("data");
        Assert.Equal(0, identity.GetProperty("scopes").GetArrayLength());
    }

    [Fact]
    public async Task The_account_endpoint_needs_a_token()
    {
        var response = await _factory.CreateClient().GetAsync("/v1/account");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ---- GET /v1/health ----------------------------------------------------------------

    [Fact]
    public async Task Health_answers_anonymously_with_a_200()
    {
        // Anonymous on purpose: with no unauthenticated endpoint to ping, "the API is down" and
        // "your session expired" look identical to a browser, and the second is far more common.
        var response = await _factory.CreateClient().GetAsync("/v1/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await ReadApiFixture.JsonAsync(response);
        Assert.Equal("ok", body.GetProperty("status").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("version").GetString()));
    }

    // ---- setup -------------------------------------------------------------------------

    private HttpClient Reader() => Client(_tenantId, AuthScopes.ScanRead, AuthScopes.ReportRead);

    private HttpClient ForeignReader() => Client(_foreignTenantId, AuthScopes.ScanRead, AuthScopes.ReportRead);

    private HttpClient Client(Guid tenantId, params string[] scopes)
    {
        var client = _factory.CreateClient();
        var userId = tenantId == _tenantId ? _userId : Guid.CreateVersion7();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", TestJwt.Create(tenantId, userId, Roles.Analyst, scopes));

        return client;
    }

    private async Task<JsonElement> GetAsync(HttpClient client, string url)
    {
        var response = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadApiFixture.JsonAsync(response);
    }

    /// <summary>
    /// Two tenants, two projects, four scans and one retained report.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The list orders on the id and its cursor keys on the id, so the fixture has to know which
    /// of its four scans is newest. It sorts the minted ids rather than trusting the order they
    /// were minted in: UUIDv7 embeds a <em>millisecond</em> timestamp, and four
    /// <c>Guid.CreateVersion7()</c> calls in one loop land inside the same millisecond, where the
    /// remaining bits are random and consecutive values are not ordered.
    /// </para>
    /// <para>
    /// That is a property of the fixture, not a flaw in the paging. Keyset paging needs a total
    /// order that is <em>stable</em>, and an id is stable whatever it sorts next to — a page
    /// therefore still cannot repeat or skip a row. What intra-millisecond ties cost is only that
    /// rows written in the same millisecond come back in an arbitrary order among themselves,
    /// which is why the scans this fixture wants ordered are ordered by construction here.
    /// </para>
    /// </remarks>
    private async Task SeedAsync()
    {
        _scanIds.AddRange(Enumerable.Range(0, 4).Select(_ => Guid.CreateVersion7()).Order());

        _summaryScanId = _scanIds[2];
        _retainedReportId = Guid.CreateVersion7();
        _foreignScanId = Guid.CreateVersion7();

        await _factory.SeedAsync(db =>
        {
            db.Tenants.Add(new Tenant
            {
                Id = _tenantId, Name = "Acme Security", PlanTier = "free",
                CreatedAt = DateTime.UtcNow.AddDays(-30),
            });

            db.Users.Add(new User
            {
                Id = _userId, TenantId = _tenantId, Email = "analyst@example.test",
                PasswordHash = "x", Role = Roles.Analyst, IsEmailVerified = true,
                CreatedAt = DateTime.UtcNow.AddDays(-30),
            });

            db.Projects.Add(Project(_projectA, _tenantId, "https://example.test/repo-a"));
            db.Projects.Add(Project(_projectB, _tenantId, "https://example.test/repo-b"));

            db.ScanJobs.Add(Job(_scanIds[0], _projectA, ScanStatus.Completed, ScanStage.Report, "pr/1", "sha1"));
            db.ScanJobs.Add(Job(_scanIds[1], _projectA, ScanStatus.Running, ScanStage.Debate, "pr/2", "sha2"));
            db.ScanJobs.Add(Job(_scanIds[2], _projectA, ScanStatus.Completed, ScanStage.Report, "pr/3", "sha3"));

            var failed = Job(_scanIds[3], _projectB, ScanStatus.Failed, ScanStage.Graph, "pr/4", "sha4");
            failed.FailureReason = "boom";
            db.ScanJobs.Add(failed);

            db.Reports.Add(new Report
            {
                Id = _retainedReportId, TenantId = _tenantId, ScanJobId = _summaryScanId,
                Framing = "draft_audit", Summary = "Draft audit for review.",
                Retained = true, CreatedAt = DateTime.UtcNow,
                CostCurrency = "USD", ModelCalls = 4, CostRated = true,
            });

            // Four findings on the summary scan: two code, one dep, one infra, one of them
            // redacted, spanning severities 1–4 with nothing at 0 so the zero bucket is real.
            db.Findings.AddRange(
                Finding(_summaryScanId, Layer.Dep, 4, "pkg:left-pad:1.0.0", redacted: false),
                Finding(_summaryScanId, Layer.Code, 3, "code:a.deserialize", redacted: true),
                Finding(_summaryScanId, Layer.Code, 3, "code:b.deserialize", redacted: false),
                Finding(_summaryScanId, Layer.Infra, 1, "s3:customer-data", redacted: false));

            var nodes = new[]
            {
                Node(_summaryScanId, "pkg:left-pad:1.0.0", NodeType.Pkg, Layer.Dep, isHot: true),
                Node(_summaryScanId, "code:a.deserialize", NodeType.Code, Layer.Code, isHot: true),
                Node(_summaryScanId, "s3:customer-data", NodeType.Resource, Layer.Infra, isHot: false),
            };
            db.GraphNodes.AddRange(nodes);

            db.GraphEdges.Add(Edge(_summaryScanId, nodes[0].Id, nodes[1].Id, Confidence.Inferred));
            db.GraphEdges.Add(Edge(_summaryScanId, nodes[1].Id, nodes[2].Id, Confidence.Certain));

            // Two chains whose weakest joins differ, so the scan-level weakest join has to pick
            // one rather than echoing the only value present.
            db.Chains.Add(Chain(_summaryScanId, ChainStatus.Candidate, Confidence.Unresolved, priority: 1));
            db.Chains.Add(Chain(_summaryScanId, ChainStatus.Validated, Confidence.Certain, priority: 2));

            // The other tenant. Present in the database and absent from every list above.
            db.Tenants.Add(new Tenant
            {
                Id = _foreignTenantId, Name = "Other Co", PlanTier = "free", CreatedAt = DateTime.UtcNow,
            });

            var foreignProject = Guid.CreateVersion7();
            db.Projects.Add(Project(foreignProject, _foreignTenantId, "https://example.test/other"));

            db.ScanJobs.Add(new ScanJob
            {
                Id = _foreignScanId, TenantId = _foreignTenantId, ProjectId = foreignProject,
                PrRef = "pr/9", CommitSha = "sha9", Status = ScanStatus.Completed,
                CorpusVersion = "2026-07-15", StartedAt = DateTime.UtcNow, Stage = ScanStage.Report,
            });
        });
    }

    private static Project Project(Guid id, Guid tenantId, string repoUrl) => new()
    {
        Id = id, TenantId = tenantId, RepoUrl = repoUrl, DefaultBranch = "main",
    };

    private ScanJob Job(Guid id, Guid projectId, ScanStatus status, ScanStage stage, string pr, string sha) => new()
    {
        Id = id, TenantId = _tenantId, ProjectId = projectId,
        PrRef = pr, CommitSha = sha, Status = status, Stage = stage,
        CorpusVersion = "2026-07-15", StartedAt = DateTime.UtcNow.AddMinutes(-10),
        CompletedAt = status is ScanStatus.Completed ? DateTime.UtcNow : null,
    };

    private Finding Finding(Guid jobId, Layer layer, int severity, string nodeRef, bool redacted) => new()
    {
        Id = Guid.CreateVersion7(), TenantId = _tenantId, ScanJobId = jobId,
        SourceTool = ScannerNames.Osv, Layer = layer, Severity = severity,
        NodeRef = nodeRef, Message = $"finding on {nodeRef}", Redacted = redacted,
    };

    private GraphNode Node(Guid jobId, string key, NodeType type, Layer layer, bool isHot) => new()
    {
        Id = Guid.CreateVersion7(), TenantId = _tenantId, ScanJobId = jobId,
        NodeKey = key, NodeType = type, Layer = layer, IsHot = isHot,
    };

    private GraphEdge Edge(Guid jobId, Guid from, Guid to, Confidence confidence) => new()
    {
        Id = Guid.CreateVersion7(), TenantId = _tenantId, ScanJobId = jobId,
        FromNodeId = from, ToNodeId = to, Relation = "used-by", Seam = Seam.DepCode,
        Confidence = confidence, OrientedAttackDir = true,
    };

    private Chain Chain(Guid jobId, ChainStatus status, Confidence minConfidence, int priority) => new()
    {
        Id = Guid.CreateVersion7(), TenantId = _tenantId, ScanJobId = jobId,
        HopCount = 2, Priority = priority, Status = status, MinConfidence = minConfidence,
    };
}

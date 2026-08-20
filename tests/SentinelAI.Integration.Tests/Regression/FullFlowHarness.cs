using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Integration.Tests.Auth;
using SentinelAI.Integration.Tests.Scan;

namespace SentinelAI.Integration.Tests.Regression;

/// <summary>
/// SEC-49: drives the golden fixture through the whole product, from the wire in to the wire
/// out, recording what each stage produced so a regression names its own stage.
/// </summary>
/// <remarks>
/// <para>
/// <b>It goes through HTTP, not through the services.</b> Every other suite here composes the
/// stage classes directly, which is right for testing a stage and wrong for this: five sprints
/// of audits found every blocking defect in a <em>seam</em> — Red never seeing real edges, the
/// UI rendering fields the backend never wrote, a bundle path that only failed once bytes
/// really moved. Composing the services by hand reconstructs the seams under test out of the
/// same assumptions that would be wrong. Posting a real tarball to <c>POST /v1/scans</c> and
/// reading the result back out of <c>GET /v1/reports/{id}</c> does not.
/// </para>
/// <para>
/// <b>One exception, stated rather than hidden.</b> The audit stage runs against
/// <c>SeedKnowledgeRetriever</c>, the offline stub the API registers when no corpus is
/// configured — a live Qdrant is a genuine external dependency and CI has none. The retrieval
/// <em>decision tree</em> is therefore exercised separately, in
/// <see cref="MeasureRetrievalAsync"/>, against the real <c>KnowledgeRetrievalService</c> over
/// the same findings this run produced and a deterministic corpus. What that measures is the
/// tree's branching over the fixture's findings, which is what SEC-49 asks for; what it does
/// not measure is the live corpus, which <c>LiveCorpusSmokeTests</c> owns.
/// </para>
/// <para>
/// <b>Deterministic and offline.</b> The scripted model provider, no network, no keys, no cost —
/// so this can run on every push, which is the only way a regression harness earns its name.
/// </para>
/// </remarks>
internal sealed class FullFlowHarness(ScanApiFactory factory)
{
    private static readonly Guid Tenant = Guid.NewGuid();

    /// <summary>Runs the whole flow once and returns what every stage did.</summary>
    public async Task<FullFlowRun> RunAsync()
    {
        var observations = new List<FullFlowObservation>();
        var run = new FullFlowRun { ScanJobId = Guid.Empty, Observations = observations };

        var projectId = await SeedProjectAsync();
        using var client = Client();

        // ---- Ingest ------------------------------------------------------------------------
        var bundle = GoldenBundle.TarGz(projectId);

        using var submit = await client.PostAsync("/v1/scans", Form(projectId, bundle));
        var submitBody = await submit.Content.ReadAsStringAsync();

        if (submit.StatusCode != HttpStatusCode.Accepted)
        {
            observations.Add(new FullFlowObservation(
                FullFlowStage.Ingest, false, $"POST /v1/scans answered {(int)submit.StatusCode}: {Trim(submitBody)}"));

            return run;
        }

        using var submitted = JsonDocument.Parse(submitBody);
        var scanJobId = Guid.Parse(submitted.RootElement.GetProperty("data").GetProperty("scanJobId").GetString()!);

        observations.Add(new FullFlowObservation(
            FullFlowStage.Ingest, true, $"202 Accepted, {bundle.Length} bytes stored, job {scanJobId}"));

        run = run with { ScanJobId = scanJobId };

        // ---- Normalize, Graph and Chain ----------------------------------------------------
        // One HTTP call produces all three, so they are read apart from its response rather
        // than driven apart — which is the finest attribution honestly available here.
        using var graph = await client.PostAsync($"/v1/scans/{scanJobId}/graph", content: null);
        var graphBody = await graph.Content.ReadAsStringAsync();

        if (graph.StatusCode != HttpStatusCode.OK)
        {
            observations.Add(new FullFlowObservation(
                FullFlowStage.Normalize, false,
                $"POST /v1/scans/{{id}}/graph answered {(int)graph.StatusCode}: {Trim(graphBody)}"));

            return run;
        }

        using var graphDocument = JsonDocument.Parse(graphBody);
        var graphData = graphDocument.RootElement.GetProperty("data");

        run = run with { FindingsByLayer = await FindingsByLayerAsync(scanJobId) };

        var findingCount = graphData.GetProperty("findings").GetInt32();

        observations.Add(new FullFlowObservation(
            FullFlowStage.Normalize,
            findingCount > 0,
            findingCount > 0
                ? $"{findingCount} finding(s): {Describe(run.FindingsByLayer)}"
                : "the bundle produced no findings at all"));

        if (findingCount == 0) return run;

        // The edges come from the read API rather than from the stage response, because only
        // the read API carries oriented_attack_dir — and edge orientation is one of the four
        // things SEC-49 is required to assert. Reversing it is the "zero-chains failure mode",
        // so reading the flag the UI reads is the point.
        using var persisted = await client.GetAsync($"/v1/scans/{scanJobId}/graph");
        var persistedBody = await persisted.Content.ReadAsStringAsync();

        if (persisted.StatusCode != HttpStatusCode.OK)
        {
            observations.Add(new FullFlowObservation(
                FullFlowStage.Graph, false,
                $"the graph stage ran but GET /v1/scans/{{id}}/graph answered "
                + $"{(int)persisted.StatusCode}: {Trim(persistedBody)}"));

            return run;
        }

        using var persistedDocument = JsonDocument.Parse(persistedBody);
        var persistedGraph = persistedDocument.RootElement;

        var edges = ReadEdges(persistedGraph);
        var nodeCount = persistedGraph.GetProperty("nodes").GetArrayLength();
        run = run with { Edges = edges };

        observations.Add(new FullFlowObservation(
            FullFlowStage.Graph,
            edges.Count > 0,
            edges.Count > 0
                ? $"{nodeCount} node(s), {edges.Count} edge(s), "
                  + $"{edges.Count(e => e.Oriented)} oriented to attack direction"
                : $"{nodeCount} node(s) and no edges — the graph is islands"));

        if (edges.Count == 0) return run;

        var chains = ReadChainPaths(graphData);
        run = run with { ChainPaths = chains };

        observations.Add(new FullFlowObservation(
            FullFlowStage.Chain,
            chains.Count > 0,
            chains.Count > 0
                ? $"{chains.Count} candidate chain(s), longest {chains.Max(c => c.Count) - 1} hop(s)"
                : "the graph has edges but no candidate chain crossed a layer"));

        if (chains.Count == 0) return run;

        // ---- Retrieval ----------------------------------------------------------------------
        var retrieval = await MeasureRetrievalAsync(scanJobId);
        run = run with { RetrievalModesThatFired = [.. retrieval.Fired] };

        observations.Add(new FullFlowObservation(
            FullFlowStage.Retrieval,
            retrieval.DidNotFire.Count == 0 && retrieval.Coverage > 0,
            $"{retrieval.Coverage:P0} of findings grounded; "
            + $"modes fired: {string.Join(", ", retrieval.Fired)}"
            + (retrieval.DidNotFire.Count > 0 ? $"; NEVER FIRED: {string.Join(", ", retrieval.DidNotFire)}" : "")));

        if (retrieval.DidNotFire.Count > 0 || retrieval.Coverage == 0) return run;

        // ---- Debate and Report ---------------------------------------------------------------
        using var audit = await client.PostAsync($"/v1/scans/{scanJobId}/audit", content: null);
        var auditBody = await audit.Content.ReadAsStringAsync();

        if (audit.StatusCode != HttpStatusCode.OK)
        {
            observations.Add(new FullFlowObservation(
                FullFlowStage.Debate, false,
                $"POST /v1/scans/{{id}}/audit answered {(int)audit.StatusCode}: {Trim(auditBody)}"));

            return run;
        }

        using var auditDocument = JsonDocument.Parse(auditBody);
        var auditData = auditDocument.RootElement.GetProperty("data");

        var rounds = auditData.GetProperty("rounds").GetInt32();
        var outcome = auditData.GetProperty("outcome").GetString()!;

        observations.Add(new FullFlowObservation(
            FullFlowStage.Debate,
            rounds > 0,
            rounds > 0
                ? $"debate {outcome} in {rounds} round(s)"
                : $"the debate produced no rounds (outcome {outcome})"));

        if (rounds == 0) return run;

        var retained = auditData.GetProperty("report_retained").GetBoolean();
        var citations = auditData.GetProperty("citations").GetInt32();
        var reportId = auditData.GetProperty("report_id").GetString();

        observations.Add(new FullFlowObservation(
            FullFlowStage.Report,
            retained && reportId is not null,
            retained
                ? $"report {reportId} retained with {citations} citation(s); "
                  + $"bundle purged: {auditData.GetProperty("bundle_purged").GetBoolean()}"
                : "the audit completed but no report was retained, so nothing can be read back"));

        if (!retained || reportId is null) return run;

        // ---- Read back -----------------------------------------------------------------------
        using var report = await client.GetAsync($"/v1/reports/{reportId}");
        var reportBody = await report.Content.ReadAsStringAsync();

        if (report.StatusCode != HttpStatusCode.OK)
        {
            observations.Add(new FullFlowObservation(
                FullFlowStage.ReadBack, false,
                $"GET /v1/reports/{{id}} answered {(int)report.StatusCode}: {Trim(reportBody)}"));

            return run;
        }

        using var reportDocument = JsonDocument.Parse(reportBody);
        var reportData = reportDocument.RootElement;

        var citedChunks = reportData.GetProperty("citations")
            .EnumerateArray()
            .Select(c => c.GetProperty("knowledge_id").GetString()!)
            .ToList();

        var reportedChains = reportData.GetProperty("chains")
            .EnumerateArray()
            .Select(c => (IReadOnlyList<string>)[.. c.GetProperty("hops").EnumerateArray()
                .OrderBy(h => h.GetInt32Property("order"))
                .Select(h => h.GetStringProperty("node_key"))
                .Where(key => key is not null)
                .Select(key => key!)])
            .ToList();

        run = run with { CitedChunkIds = citedChunks, ReportedChainPaths = reportedChains };

        observations.Add(new FullFlowObservation(
            FullFlowStage.ReadBack,
            reportedChains.Count > 0,
            reportedChains.Count > 0
                ? $"the read API serves {reportedChains.Count} chain(s) and {citedChunks.Count} citation(s)"
                : "the report reads back with no chains, so the screen would render an empty audit"));

        return run;
    }

    // ---- the pieces ------------------------------------------------------------------------

    private async Task<Guid> SeedProjectAsync()
    {
        var projectId = Guid.CreateVersion7();

        await factory.SeedAsync(db => db.Projects.Add(new Project
        {
            Id = projectId,
            TenantId = Tenant,
            RepoUrl = $"https://example.test/sentinelai-fixtures/{projectId}",
            DefaultBranch = "main",
        }));

        return projectId;
    }

    /// <summary>
    /// A machine token carrying every scope the flow needs.
    /// </summary>
    /// <remarks>
    /// One token for the whole run, deliberately. Which scope each endpoint requires is
    /// <c>ReadApiTenantIsolationTests</c>'s subject; splitting it here would make a scope
    /// regression surface as a stage failure in the wrong stage.
    /// </remarks>
    private HttpClient Client()
    {
        var client = factory.CreateClient();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            TestJwt.Create(
                Tenant,
                userId: Guid.NewGuid(),
                role: Roles.Analyst,
                scopes: [AuthScopes.ScanWrite, AuthScopes.ScanRead, AuthScopes.ReportRead]));

        return client;
    }

    private static MultipartFormDataContent Form(Guid projectId, byte[] bundle)
    {
        var content = new MultipartFormDataContent
        {
            { new StringContent(GoldenBundle.MetadataJson(projectId, "49c0ffee")), "metadata" },
        };

        var file = new ByteArrayContent(bundle);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/gzip");
        content.Add(file, "bundle", "bundle.tar.gz");

        return content;
    }

    private async Task<IReadOnlyDictionary<string, int>> FindingsByLayerAsync(Guid scanJobId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();

        var findings = await db.Findings.IgnoreQueryFilters()
            .Where(f => f.ScanJobId == scanJobId)
            .Select(f => f.Layer)
            .ToListAsync();

        return findings
            .GroupBy(layer => layer.ToString())
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);
    }

    /// <summary>
    /// Runs SEC-22's real decision tree over the findings this scan produced, in both embedder
    /// configurations, and measures which arms answered.
    /// </summary>
    /// <remarks>
    /// The findings come from the database rather than from a constant, so this measures the
    /// tree against what the pipeline actually normalized — including the CWE the rule-mapping
    /// table resolved, which is the input the exact arm branches on and the one most likely to
    /// regress silently.
    /// </remarks>
    private async Task<RetrievalMeasurement> MeasureRetrievalAsync(Guid scanJobId)
    {
        List<Finding> findings;

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();

            findings = await db.Findings.IgnoreQueryFilters()
                .Where(f => f.ScanJobId == scanJobId)
                .ToListAsync();
        }

        var results = new List<RetrievalResult>();

        foreach (var embedder in new[] { RegressionEmbedder.DenseOnly(), RegressionEmbedder.Hybrid() })
        {
            var service = new KnowledgeRetrievalService(
                new RetrievalQueryBuilder(),
                new RegressionCorpus(),
                embedder,
                NullLogger<KnowledgeRetrievalService>.Instance);

            foreach (var role in new[] { AgentRole.Red, AgentRole.Blue })
            {
                var intent = AgentRetrieval.IntentFor(role)!.Value;
                results.AddRange(await service.RetrieveAllAsync(findings, intent));
            }
        }

        var evaluation = RetrievalEvaluation.Of(results);

        return new RetrievalMeasurement(
            Fired: [.. RetrievalEvaluation.AnsweringModes
                .Where(mode => evaluation.ByMode[mode] > 0)
                .Select(mode => mode.ToString())],
            DidNotFire: [.. evaluation.ModesThatDidNotFire.Select(mode => mode.ToString())],
            Coverage: evaluation.GroundingCoverage);
    }

    private sealed record RetrievalMeasurement(
        IReadOnlyList<string> Fired, IReadOnlyList<string> DidNotFire, double Coverage);

    /// <summary>The persisted graph as the read API serves it, orientation flag included.</summary>
    private static List<(string From, string Relation, string To, bool Oriented)> ReadEdges(JsonElement graph) =>
    [
        .. graph.GetProperty("edges").EnumerateArray().Select(e => (
            From: e.GetStringProperty("from") ?? "?",
            Relation: e.GetStringProperty("relation") ?? "?",
            To: e.GetStringProperty("to") ?? "?",
            Oriented: e.TryGetProperty("oriented_attack_dir", out var oriented)
                && oriented.ValueKind == JsonValueKind.True)),
    ];

    private static List<IReadOnlyList<string>> ReadChainPaths(JsonElement graphData) =>
    [
        .. graphData.GetProperty("chains").EnumerateArray().Select(c =>
            (IReadOnlyList<string>)[.. c.GetProperty("path").EnumerateArray().Select(p => p.GetString()!)]),
    ];

    private static string Describe(IReadOnlyDictionary<string, int> byLayer) =>
        byLayer.Count == 0
            ? "none"
            : string.Join(", ", byLayer.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}={kv.Value}"));

    private static string Trim(string body) => body.Length <= 400 ? body : body[..400] + "…";
}

/// <summary>Small readers that tolerate a missing property instead of throwing mid-diagnosis.</summary>
/// <remarks>
/// A harness whose own reader throws on an unexpected payload reports a <c>KeyNotFoundException</c>
/// where it should report "the read API stopped sending node_key" — the field being gone is the
/// regression, and it deserves to be named rather than to crash the run that found it.
/// </remarks>
internal static class JsonElementReaders
{
    public static string? GetStringProperty(this JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    public static int GetInt32Property(this JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number
            ? value.GetInt32()
            : 0;
}

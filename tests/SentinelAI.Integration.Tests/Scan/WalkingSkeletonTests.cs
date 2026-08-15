using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Reporting;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Application.Features.Scan.ThinSlice;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Knowledge;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// SEC-45 — the walking skeleton. One seeded finding travels normalize → graph → retrieve →
/// debate → report, and every seam between them is asserted.
/// </summary>
/// <remarks>
/// <para>
/// These tests are about <em>joins</em>, not about quality. Nothing here checks that the graph
/// is insightful or the debate correct — every stage is a stub and is supposed to be. What is
/// checked is that each stage accepts what the previous one produced, in the shape it produced
/// it, so that deepening any one of them later is a change inside that stage.
/// </para>
/// <para>
/// The debate runs on the scripted provider, so this is deterministic and offline. That matters:
/// a walking-skeleton test that needs a live model is a test nobody runs.
/// </para>
/// </remarks>
public class WalkingSkeletonTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    /// <summary>
    /// The seeded finding from the SEC-45 spec: unsafe deserialization in OrderService, the
    /// fixture's flagship. Built through <see cref="NodeId"/>, never by concatenation.
    /// </summary>
    private static Finding SeededFinding() => new()
    {
        Id = Guid.CreateVersion7(),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = ScannerNames.Roslyn,
        CheckId = "SCS0028",
        Layer = Layer.Code,
        Severity = 4,
        CweId = "CWE-502",
        CveId = null,
        NodeRef = NodeId.Code("OrderService"),
        Message = "Unsafe deserialization in OrderService",
    };

    private static ThinSlicePipeline Build(IDebateEngine? debate = null) =>
        new(new GraphSeeder(),
            new RetrievalQueryBuilder(),
            new SeedKnowledgeRetriever(NullLogger<SeedKnowledgeRetriever>.Instance),
            new ScanBriefRenderer(),
            debate ?? new ScriptedDebate(),
            new ReportBuilder(),
            NullLogger<ThinSlicePipeline>.Instance);

    // ---- Acceptance box 1: one finding travels all five stages -----------------------------

    [Fact]
    public async Task One_seeded_finding_reaches_every_stage()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        Assert.Single(result.Findings);                      // normalize
        Assert.Single(result.Nodes);                         // graph
        Assert.NotEmpty(result.Knowledge);                   // retrieve
        Assert.NotNull(result.Audit);                        // debate
        Assert.NotNull(result.Report);                       // report

        // Not merely non-null at each step — the finding's own content is visible at the end.
        Assert.Equal("code:orderservice", result.Nodes[0].NodeKey);
        Assert.Contains(result.Knowledge, k => k.Contains("CWE-502", StringComparison.Ordinal));
        Assert.Contains(result.Report.Citations, c => c.KnowledgeId == "CWE-502");
    }

    // ---- Acceptance box 2: no seam is broken ----------------------------------------------

    [Fact]
    public async Task Seam_normalize_to_graph_every_finding_lands_on_a_node()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        var nodeKeys = result.Nodes.Select(n => n.NodeKey).ToHashSet(StringComparer.Ordinal);

        // The join is by exact string. If the finding said code:OrderService and the node said
        // code:orderservice, both would look fine in isolation and never meet (SEC-03).
        Assert.All(result.Findings, f => Assert.Contains(f.NodeRef, nodeKeys));
        Assert.All(result.Nodes, n => Assert.True(NodeId.IsCanonical(n.NodeKey), n.NodeKey));

        // The node's declared type agrees with the key it is found by.
        Assert.All(result.Nodes, n =>
        {
            Assert.True(NodeId.TryParse(n.NodeKey, out var parsed, out _));
            Assert.Equal(n.NodeType, parsed);
        });
    }

    [Fact]
    public async Task Seam_graph_to_retrieve_the_query_is_keyed_on_the_findings_linking_key()
    {
        var spy = new SpyRetriever();
        var pipeline = new ThinSlicePipeline(
            new GraphSeeder(), new RetrievalQueryBuilder(), spy, new ScanBriefRenderer(),
            new ScriptedDebate(), new ReportBuilder(), NullLogger<ThinSlicePipeline>.Instance);

        await pipeline.RunAsync([SeededFinding()], Tenant, Job);

        // Two queries for one finding since SEC-23: Red asks offense, Blue asks defense. Same
        // question, both halves of the corpus — the split is by role, never by tool.
        Assert.Equal(2, spy.Queries.Count);
        Assert.All(spy.Queries, q => Assert.StartsWith("CWE-502", q.Text, StringComparison.Ordinal));

        Assert.Equal(
            ["offense", "defense"],
            spy.Queries.Select(q => q.Collection));
    }

    [Fact]
    public async Task Seam_retrieve_to_debate_the_brief_carries_the_nodes_and_the_knowledge()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        // The agents learn the node vocabulary from this text. If a key were re-spelled here,
        // Red would assert chains whose ids the real graph can never match.
        Assert.Contains("code:orderservice", result.Brief.Context, StringComparison.Ordinal);
        Assert.Contains("CWE-502", result.Brief.Context, StringComparison.Ordinal);
        Assert.Equal(Job.ToString(), result.Brief.ScanJobId);

        // Every node key in the brief is one this codebase could have produced.
        Assert.All(result.Nodes, n => Assert.Contains(n.NodeKey, result.Brief.Context, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Seam_debate_to_report_the_audit_reaches_the_report_with_its_framing_intact()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        Assert.Equal(ReportBuilder.DraftAudit, result.Report.Framing);
        Assert.Contains(result.Audit.Summary, result.Report.Summary, StringComparison.Ordinal);

        // AID-01 §7: the draft framing is non-negotiable and travels in the text, not in a
        // field a renderer could forget to show.
        Assert.Contains(result.Audit.Disclaimer, result.Report.Summary, StringComparison.Ordinal);
        Assert.Contains("not a verified verdict", result.Report.Summary, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(Job, result.Report.ScanJobId);
        Assert.Equal(Tenant, result.Report.TenantId);
        Assert.All(result.Report.Citations, c => Assert.Equal(Tenant, c.TenantId));
    }

    [Fact]
    public async Task Seam_report_cites_only_knowledge_that_was_actually_retrieved()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        Assert.Equal(result.Knowledge.Count, result.Report.Citations.Count);
        Assert.All(result.Report.Citations, c => Assert.False(string.IsNullOrWhiteSpace(c.KnowledgeId)));
        Assert.All(result.Report.Citations, c => Assert.Equal(ThinSlicePipeline.Collection, c.Collection));
    }

    [Fact]
    public async Task A_finding_the_corpus_has_nothing_for_still_reaches_the_report()
    {
        // Empty retrieval is a normal answer, not a failure, and the real retriever will return
        // it too. The pipe must not stall on it, and the report must not claim sources.
        var finding = SeededFinding();
        finding.CweId = "CWE-99999";

        var result = await Build().RunAsync([finding], Tenant, Job);

        Assert.Empty(result.Knowledge);
        Assert.Empty(result.Report.Citations);
        Assert.NotNull(result.Report);
        Assert.Equal(ReportBuilder.DraftAudit, result.Report.Framing);
    }

    // ---- Acceptance box 3: the boundary shapes are fixed and tested -------------------------

    [Fact]
    public async Task Every_stage_output_is_present_and_typed()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        // The shape each stage must keep producing when it is deepened later. A stage that
        // starts returning null or an empty collection breaks here rather than silently
        // producing an empty report.
        Assert.NotEmpty(result.Findings);
        Assert.NotEmpty(result.Nodes);
        Assert.NotEmpty(result.Knowledge);
        Assert.False(string.IsNullOrWhiteSpace(result.Brief.Context));
        Assert.False(string.IsNullOrWhiteSpace(result.Audit.Summary));
        Assert.False(string.IsNullOrWhiteSpace(result.Report.Summary));
    }

    [Fact]
    public async Task A_finding_whose_node_reference_could_not_be_built_by_NodeId_stops_the_pipe()
    {
        // The one place the skeleton is deliberately loud. A finding that cannot join the graph
        // is invisible to every stage after it, so this must not be a silent skip.
        var finding = SeededFinding();
        finding.NodeRef = "Code:OrderService";     // hand-built: wrong case, not canonical

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build().RunAsync([finding], Tenant, Job));

        Assert.Contains("could never join the graph", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Several_findings_on_one_node_produce_one_node_and_it_is_hot()
    {
        var low = SeededFinding();
        low.Severity = 1;
        low.Message = "A cool finding on the same code.";

        var result = await Build().RunAsync([low, SeededFinding()], Tenant, Job);

        var node = Assert.Single(result.Nodes);
        Assert.True(node.IsHot, "a high-severity finding on the node must make it hot");
    }

    // ---- Test doubles ----------------------------------------------------------------------

    /// <summary>
    /// A debate that returns a fixed audit. The real engine is exercised by SEC-02's own
    /// acceptance tests; what this one needs is a deterministic <see cref="DraftAudit"/> so the
    /// debate → report seam can be asserted without the workflow's timing in the way.
    /// </summary>
    private sealed class ScriptedDebate : IDebateEngine
    {
        public ScanBrief? Received { get; private set; }

        public Task<DraftAudit> RunAsync(ScanBrief brief, CancellationToken ct = default)
        {
            Received = brief;

            return Task.FromResult(new DraftAudit
            {
                Summary = "Walking skeleton: one finding, one node, no edges, no chain asserted.",
                Transcript =
                [
                    new DebateTurn { Role = AgentRole.Red, Round = 1, Content = "ASSERT: nothing to chain — no edges." },
                    new DebateTurn { Role = AgentRole.Blue, Round = 1, Content = "VALIDATE: agreed, no chain to break." },
                ],
                Rounds = 1,
                TerminatedByTurnCap = false,
                Converged = true,
                WeakestJoin = Confidence.Unresolved,
            });
        }
    }

    private sealed record RetrievalCall(string Text, string Collection);

    /// <summary>
    /// Records what SEC-21 would build for each finding the pipeline seeds retrieval with.
    /// </summary>
    /// <remarks>
    /// The seam carries the finding now, not a pre-built string, because the exact-filter arm
    /// needs the identifiers as values. The query is rebuilt here with the same builder the real
    /// retriever uses, so these assertions still describe the text that reaches the corpus.
    /// </remarks>
    private sealed class SpyRetriever : IKnowledgeRetriever
    {
        private readonly RetrievalQueryBuilder _queries = new();

        public List<RetrievalCall> Queries { get; } = [];

        public Task<RetrievalResult> RetrieveAsync(
            Finding finding, RetrievalIntent intent, CancellationToken ct = default)
        {
            Queries.Add(new RetrievalCall(_queries.Build(finding) ?? string.Empty, intent.Collection().Wire()));

            return Task.FromResult(new RetrievalResult(
                finding.Id, RetrievalMode.ExactFilter,
                [new KnowledgeChunk("CWE-502", KnowledgeSource.Cwe, "CWE-502", "canned", 0f)],
                []));
        }
    }
}

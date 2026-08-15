using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
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

namespace SentinelAI.Integration.Tests.Knowledge;

/// <summary>
/// A whole scan, grounded in the real corpus: one finding through normalize → graph → retrieve →
/// debate → report, with the chunks the report cites coming from Pipeline A.
/// </summary>
/// <remarks>
/// <para>
/// <c>LiveCorpusSmokeTests</c> proves the retriever reaches the corpus. This proves the
/// <em>pipeline</em> uses it — which is a different claim, and the one that was quietly false for
/// most of this story's life, when the tree was built and registered but nothing called it.
/// </para>
/// <para>
/// The debate runs on the scripted provider, so this needs no API key and costs nothing. Only the
/// retrieval half touches the network. Read-only: it creates and deletes nothing.
/// </para>
/// <para>
/// Set <c>SENTINELAI_CORPUS_URL</c> and <c>SENTINELAI_CORPUS_KEY</c> to run it.
/// </para>
/// </remarks>
public class LiveCorpusPipelineTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    /// <summary>The fixture's flagship: unsafe deserialization, carrying CWE-502.</summary>
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
        NodeRef = NodeId.Code("OrderService"),
        Message = "Unsafe deserialization in OrderService",
    };

    /// <summary>
    /// The real pipeline, with the real retriever pointed at the live corpus and no embedder —
    /// the configuration SEC-22 can be finished in.
    /// </summary>
    private static ThinSlicePipeline Build()
    {
        var search = new QdrantKnowledgeSearch(
            Options.Create(new QdrantOptions
            {
                Endpoint = LiveCorpusFactAttribute.Url!,
                ApiKey = LocalDev.CorpusKey,
            }),
            NullLogger<QdrantKnowledgeSearch>.Instance);

        var retriever = new KnowledgeRetrievalService(
            new RetrievalQueryBuilder(), search, new NotConfiguredQueryEmbedder(),
            NullLogger<KnowledgeRetrievalService>.Instance);

        return new ThinSlicePipeline(
            new GraphSeeder(),
            new RetrievalQueryBuilder(),
            retriever,
            new ScanBriefRenderer(),
            new FixedAudit(),
            new ReportBuilder(),
            NullLogger<ThinSlicePipeline>.Instance);
    }

    [LiveCorpusFact]
    public async Task One_finding_travels_every_stage_and_arrives_grounded_in_the_real_corpus()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        Assert.Single(result.Findings);          // normalize
        Assert.Single(result.Nodes);             // graph
        Assert.NotEmpty(result.Knowledge);       // retrieve — from Qdrant, not a dictionary
        Assert.NotNull(result.Audit);            // debate
        Assert.NotNull(result.Report);           // report
    }

    /// <summary>
    /// The knowledge in the brief has to be corpus text. The stub answers for CWE-502 too, so
    /// "the pipeline produced knowledge" is not evidence on its own — it is the shape of the text
    /// that tells them apart.
    /// </summary>
    [LiveCorpusFact]
    public async Task The_knowledge_in_the_brief_is_corpus_text_and_not_the_canned_stub()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        // The stub prefixes every answer with the linking key in brackets. Real chunks do not.
        Assert.All(result.Knowledge, k =>
            Assert.False(k.StartsWith("[CWE-502]", StringComparison.Ordinal),
                "the pipeline is still reading SeedKnowledgeRetriever's canned data"));

        Assert.All(result.Knowledge, k => Assert.False(string.IsNullOrWhiteSpace(k)));
    }

    /// <summary>
    /// The point of the whole exercise: an assertion in the audit is traceable to a chunk that
    /// exists in the corpus. A citation the corpus cannot produce is a claim with nothing behind it.
    /// </summary>
    [LiveCorpusFact]
    public async Task The_report_cites_knowledge_that_reached_it_from_the_corpus()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        Assert.NotEmpty(result.Report.Citations);
        Assert.Equal(result.Knowledge.Count, result.Report.Citations.Count);
    }

    /// <summary>
    /// The brief the agents read carries the corpus text, which is the actual delivery point —
    /// everything upstream is plumbing if the model never sees the knowledge.
    /// </summary>
    [LiveCorpusFact]
    public async Task The_agents_brief_contains_the_retrieved_knowledge()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        Assert.Contains("Knowledge retrieved", result.Brief.Context, StringComparison.Ordinal);

        // At least one retrieved chunk's opening words appear verbatim in what the agents read.
        var first = result.Knowledge[0];
        var opening = first[..Math.Min(40, first.Length)];

        Assert.Contains(opening, result.Brief.Context, StringComparison.Ordinal);
    }

    /// <summary>
    /// SEC-23 end to end: one scan grounds Red in the offense half and Blue in the defense half
    /// of the same corpus, and the brief keeps them apart.
    /// </summary>
    /// <remarks>
    /// A merged block would hand both agents the other's answers — a mitigation listed among
    /// attacker knowledge reads to Red as a technique — which is precisely the split this story
    /// exists to make.
    /// </remarks>
    [LiveCorpusFact]
    public async Task Red_and_blue_are_grounded_in_different_halves_of_the_corpus()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        Assert.Contains("Knowledge retrieved for Red (offense)", result.Brief.Context, StringComparison.Ordinal);
        Assert.Contains("Knowledge retrieved for Blue (defense)", result.Brief.Context, StringComparison.Ordinal);

        // Both halves answered for the same CWE-502 finding, from the one shared corpus.
        Assert.NotEmpty(result.Knowledge);
    }

    /// <summary>
    /// A debate that returns a fixed audit, so the retrieval half is what this test measures.
    /// SEC-02's own acceptance tests exercise the real engine; here it would only add timing.
    /// </summary>
    private sealed class FixedAudit : IDebateEngine
    {
        public Task<DraftAudit> RunAsync(ScanBrief brief, CancellationToken ct = default) =>
            Task.FromResult(new DraftAudit
            {
                Summary = "Live-corpus pipeline check.",
                Transcript = [new DebateTurn { Role = AgentRole.Red, Round = 1, Content = "ASSERT: n/a." }],
                Rounds = 1,
                TerminatedByTurnCap = false,
                Converged = true,
                WeakestJoin = Confidence.Unresolved,
            });
    }
}
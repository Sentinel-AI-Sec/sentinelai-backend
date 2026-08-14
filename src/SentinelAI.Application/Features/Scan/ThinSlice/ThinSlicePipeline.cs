using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Reporting;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.ThinSlice;

/// <summary>
/// The walking skeleton (SEC-45): pushes findings through every stage of the backend —
/// normalize, graph, retrieve, debate, report — with each stage the thinnest version that is
/// still honest.
/// </summary>
/// <remarks>
/// <para>
/// The goal is not that any stage is smart. It is that every seam exists, fits, and is pinned
/// by a test now, so that deepening a stage later is a change inside that stage rather than a
/// renegotiation with its neighbours. Integration defects are the expensive kind and they stay
/// hidden until the end if nothing forces the joins to close early.
/// </para>
/// <para>
/// Normalization is <em>not</em> re-run here. It is a real stage now (SEC-14/15/16) with its
/// own pipeline, and its output — one deduplicated set of findings, each carrying a canonical
/// node reference — is this one's input. That is the seam, and taking findings as a parameter
/// is what keeps it a seam rather than a merge.
/// </para>
/// </remarks>
public sealed class ThinSlicePipeline(
    GraphSeeder graphSeeder,
    IKnowledgeRetriever retriever,
    ScanBriefRenderer briefRenderer,
    IDebateEngine debate,
    ReportBuilder reportBuilder,
    ILogger<ThinSlicePipeline> logger)
{
    /// <summary>The collection the offensive knowledge is retrieved from (SEC-09).</summary>
    public const string Collection = "offense";

    /// <summary>
    /// How many findings seed retrieval. The debate reasons over a bounded brief — AID-01 §3.2
    /// caps candidate chains rather than handing over the free graph — so this takes the most
    /// severe few instead of every finding a large repository produces.
    /// </summary>
    public const int RetrievalSeedCount = 5;

    /// <param name="graph">
    /// The resource graph to reason over, when one already exists. Null means "seed one from the
    /// findings" — see <see cref="GraphFor"/>, which is where the difference between the two
    /// callers of this pipeline lives.
    /// </param>
    public async Task<ThinSliceResult> RunAsync(
        IReadOnlyList<Finding> findings,
        Guid tenantId,
        Guid scanJobId,
        IReadOnlyList<GraphNode>? graph = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(findings);

        // ---- Stage 2: graph ---------------------------------------------------------------
        var nodes = GraphFor(findings, graph, tenantId, scanJobId);

        // ---- Stage 3: retrieve ------------------------------------------------------------
        var knowledge = await RetrieveAsync(findings, ct);

        // ---- Stage 4: debate --------------------------------------------------------------
        var brief = briefRenderer.Render(scanJobId, findings, nodes, knowledge);
        var audit = await debate.RunAsync(brief, ct);

        // ---- Stage 5: report --------------------------------------------------------------
        var report = reportBuilder.Build(
            audit, knowledge, tenantId, scanJobId, Collection, DateTime.UtcNow);

        logger.LogInformation(
            "Thin slice for job {JobId}: {Findings} finding(s) -> {Nodes} node(s) -> "
            + "{Chunks} knowledge chunk(s) -> debate {Outcome} in {Rounds} round(s) -> "
            + "report with {Citations} citation(s)",
            scanJobId, findings.Count, nodes.Count, knowledge.Count,
            audit.Outcome, audit.Rounds, report.Citations.Count);

        return new ThinSliceResult
        {
            Findings = findings,
            Nodes = nodes,
            Knowledge = knowledge,
            Brief = brief,
            Audit = audit,
            Report = report,
        };
    }

    /// <summary>
    /// One retrieval per linking key on the most severe findings, de-duplicated.
    /// </summary>
    /// <remarks>
    /// Queries are built from the linking key plus the message, not from the message alone: the
    /// id is what the corpus can match exactly, and the prose is what makes a meaning-based
    /// search useful once there is one. A finding with neither a CWE nor a CVE is skipped — it
    /// has nothing the corpus can be keyed on, which is the gap SEC-15's table exists to close.
    /// </remarks>
    private async Task<IReadOnlyList<string>> RetrieveAsync(
        IReadOnlyList<Finding> findings, CancellationToken ct)
    {
        var chunks = new List<string>();
        var seenQueries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unlinked = 0;

        foreach (var finding in findings.OrderByDescending(f => f.Severity).Take(RetrievalSeedCount))
        {
            var key = finding.CweId ?? finding.CveId;
            if (key is null)
            {
                unlinked++;
                continue;
            }

            var query = $"{key} {finding.Message}";
            if (!seenQueries.Add(query))
                continue;

            foreach (var chunk in await retriever.RetrieveAsync(query, Collection, ct))
                if (!chunks.Contains(chunk, StringComparer.Ordinal))
                    chunks.Add(chunk);
        }

        if (unlinked > 0)
        {
            logger.LogInformation(
                "{Count} of the seeded finding(s) carried no CWE or CVE, so nothing could be "
                + "retrieved for them", unlinked);
        }

        return chunks;
    }
}

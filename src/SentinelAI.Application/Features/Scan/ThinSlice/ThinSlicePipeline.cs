using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Reporting;
using SentinelAI.Application.Features.Scan.Retrieval;
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
    RetrievalQueryBuilder queryBuilder,
    IKnowledgeRetriever retriever,
    ScanBriefRenderer briefRenderer,
    IDebateEngine debate,
    ReportBuilder reportBuilder,
    ILogger<ThinSlicePipeline> logger)
{
    /// <summary>The collection the offensive knowledge is retrieved from (SEC-09).</summary>
    /// <remarks>Kept as a string because <c>ReportBuilder</c> stamps it on every citation.</remarks>
    public const string Collection = "offense";

    /// <summary>
    /// What the skeleton asks the corpus, per agent (SEC-23).
    /// </summary>
    /// <remarks>
    /// Red asks the attacker question against offense and Blue the remediation question against
    /// defense, so each is grounded in the half of the corpus its job needs. Which collection
    /// that is comes from <see cref="AgentRetrieval"/> — never from which tool reported the
    /// finding, which is the split SEC-23 exists to prevent.
    /// </remarks>
    public static IReadOnlyList<AgentRole> RetrievingRoles => AgentRetrieval.RetrievingRoles;

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
    /// <param name="candidates">
    /// The candidate chains SEC-20's traverser found over that graph, when it has run. Null or
    /// empty produces an empty <see cref="AttackGraphHandoff"/> rather than none — the walking
    /// skeleton has no edges and therefore no paths, and "no candidates" is a fact the later
    /// stages should read, not a null they should guard.
    /// </param>
    public async Task<ThinSliceResult> RunAsync(
        IReadOnlyList<Finding> findings,
        Guid tenantId,
        Guid scanJobId,
        IReadOnlyList<GraphNode>? graph = null,
        IReadOnlyList<CandidateChain>? candidates = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(findings);

        // ---- Stage 2: graph ---------------------------------------------------------------
        var nodes = GraphFor(findings, graph, tenantId, scanJobId);
        var handoff = AttackGraphHandoff.From(tenantId, scanJobId, candidates ?? []);

        // ---- Stage 3: retrieve, once per agent (SEC-23) -----------------------------------
        var byRole = new Dictionary<AgentRole, IReadOnlyList<string>>();
        foreach (var role in RetrievingRoles)
            byRole[role] = await RetrieveAsync(findings, handoff, role, ct);

        // The union, for the report's citations: a chunk cited by either agent is knowledge the
        // audit rests on, and the report does not care which of them fetched it.
        var knowledge = byRole.Values
            .SelectMany(chunks => chunks)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        // ---- Stage 4: debate --------------------------------------------------------------
        var brief = briefRenderer.Render(scanJobId, findings, nodes, byRole);
        var audit = await debate.RunAsync(brief, ct);

        // ---- Stage 5: report --------------------------------------------------------------
        var report = reportBuilder.Build(
            audit, knowledge, tenantId, scanJobId, Collection, DateTime.UtcNow);

        logger.LogInformation(
            "Thin slice for job {JobId}: {Findings} finding(s) -> {Nodes} node(s) -> "
            + "{Candidates} candidate chain(s) -> {Chunks} knowledge chunk(s) -> debate {Outcome} "
            + "in {Rounds} round(s) -> report with {Citations} citation(s)",
            scanJobId, findings.Count, nodes.Count, handoff.Candidates.Count, knowledge.Count,
            audit.Outcome, audit.Rounds, report.Citations.Count);

        return new ThinSliceResult
        {
            Findings = findings,
            Nodes = nodes,
            Handoff = handoff,
            Knowledge = knowledge,
            Brief = brief,
            Audit = audit,
            Report = report,
        };
    }

    /// <summary>
    /// The node set this run reasons over: the real graph when the caller already built one,
    /// otherwise a set seeded from the findings themselves.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two callers, two situations. The graph stage (SEC-17→SEC-20) builds a structural graph
    /// from Terraform, lock files and Dockerfiles, and its nodes are the ones a chain is actually
    /// traversed over — when that has run, this pipeline must reason over <em>those</em> nodes and
    /// not invent a second set beside them. The walking skeleton (SEC-45) has no such graph and
    /// seeds one node per distinct finding reference, which is thin but honest.
    /// </para>
    /// <para>
    /// An empty supplied graph is treated as "no graph", not as "a graph with nothing in it".
    /// Reasoning over zero nodes produces a brief with no resources in it and a debate about
    /// nothing, which reads as a clean scan — the zero-chains failure mode wearing a different
    /// hat. Falling back to the seeder keeps the findings visible.
    /// </para>
    /// <para>
    /// <see cref="GraphSeeder.Seed"/> throws when a finding carries a node reference
    /// <c>NodeId</c> could not have produced, rather than dropping it: a finding that cannot join
    /// the graph is invisible to every later stage, and silence is the failure mode SEC-03 exists
    /// to prevent.
    /// </para>
    /// </remarks>
    private IReadOnlyList<GraphNode> GraphFor(
        IReadOnlyList<Finding> findings, IReadOnlyList<GraphNode>? graph, Guid tenantId, Guid scanJobId)
    {
        if (graph is { Count: > 0 })
        {
            logger.LogInformation(
                "Thin slice for job {JobId} is reasoning over the {Count} node(s) the graph stage "
                + "built, rather than seeding its own", scanJobId, graph.Count);
            return graph;
        }

        return graphSeeder.Seed(findings, tenantId, scanJobId);
    }

    /// <summary>
    /// One retrieval per seeded finding, de-duplicated on the query text.
    /// </summary>
    /// <remarks>
    /// The queries come from <see cref="RetrievalQueryBuilder"/> (SEC-21), which is what keeps the
    /// scanner's own scaffolding out of the corpus search; this method owns only which findings
    /// get one and what is done with the answers. A finding the builder returns null for is
    /// skipped and counted — it has nothing the corpus can be keyed on, which is the gap SEC-15's
    /// table exists to close.
    /// </remarks>
    private async Task<IReadOnlyList<string>> RetrieveAsync(
        IReadOnlyList<Finding> findings, AttackGraphHandoff handoff, AgentRole role,
        CancellationToken ct)
    {
        var chunks = new List<string>();
        var seenQueries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unlinked = 0;

        foreach (var finding in Seeds(findings, handoff))
        {
            var query = queryBuilder.Build(finding);
            if (query is null)
            {
                unlinked++;
                continue;
            }

            if (!seenQueries.Add(query))
                continue;

            // SEC-22's decision tree when a corpus is configured, the canned stub when it is
            // not — the seam is the same either way, which is what the walking skeleton
            // established it for.
            var result = await retriever.RetrieveAsync(finding, AgentRetrieval.IntentFor(role)!.Value, ct);

            foreach (var text in result.Chunks.Select(c => $"[{c.ChunkId}] {c.Text}"))
                if (!chunks.Contains(text, StringComparer.Ordinal))
                    chunks.Add(text);
        }

        if (unlinked > 0)
        {
            logger.LogInformation(
                "{Count} of the seeded finding(s) carried no CWE or CVE, so nothing could be "
                + "retrieved for {Role}", unlinked, role);
        }

        return chunks;
    }

    /// <summary>
    /// The findings worth spending the <see cref="RetrievalSeedCount"/> retrievals on: the ones on
    /// a candidate attack path first, then the rest by severity.
    /// </summary>
    /// <remarks>
    /// A severity-4 finding sitting on no path and a severity-4 finding two hops from the crown
    /// jewel are not equally worth retrieving for — the debate reasons inside the candidates, so
    /// knowledge about a finding on one of them is knowledge it can use. The tail is kept rather
    /// than discarded because a scan with no chains at all (no edges extracted, or none that
    /// crossed a layer) would otherwise retrieve nothing and produce a report with no citations,
    /// which reads exactly like a clean scan.
    /// </remarks>
    private static IEnumerable<Finding> Seeds(IReadOnlyList<Finding> findings, AttackGraphHandoff handoff) =>
        handoff.Findings
            .Concat(findings.OrderByDescending(f => f.Severity))
            .Distinct()
            .Take(RetrievalSeedCount);
}

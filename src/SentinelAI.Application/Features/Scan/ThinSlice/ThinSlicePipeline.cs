using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Abstractions.Billing;
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
    IScanRetentionPolicy retention,
    ITenantEntitlements entitlements,
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
    /// <param name="edges">
    /// The graph's edges, when <paramref name="graph"/> is the real one the graph stage built.
    /// Null or empty renders the brief's explicit "no edges, do not infer one" policy — which is
    /// correct for the walking skeleton's seeded nodes, and wrong for a real graph that simply
    /// was not passed one. There is no seeded fallback for this parameter the way there is for
    /// <paramref name="graph"/>: the seeder produces nodes with no structural relationship
    /// between them, so a fabricated edge would be a fabricated hop (SEC-26).
    /// </param>
    /// <summary>
    /// The audit a scan gets when its plan does not include adjudication.
    /// </summary>
    /// <remarks>
    /// The summary is written for the customer reading the report, and it says what did happen as
    /// well as what did not — a report that only names the missing feature reads like an error.
    /// It deliberately claims nothing about the chains: they stay <c>candidate</c>, which is the
    /// true word for a path nobody has argued over.
    /// </remarks>
    private static DraftAudit DraftAuditNotAdjudicated(string planId, string corpusVersion) => new()
    {
        Summary =
            $"Adjudication is not included on the {planId} plan, so no Red/Blue debate was run "
            + "over this scan. The findings and the resource graph below are complete; the "
            + "candidate chains have not been asserted, confirmed or refuted by anyone, and are "
            + "listed as candidates for that reason.",
        Transcript = [],
        Rounds = 0,
        TerminatedByTurnCap = false,
        Converged = false,
        Adjudicated = false,
        CorpusVersion = corpusVersion,
    };

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
        IReadOnlyList<GraphEdge>? edges = null,
        IReadOnlyList<CandidateChain>? candidates = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(findings);

        // ---- Stage 2: graph ---------------------------------------------------------------
        var nodes = GraphFor(findings, graph, tenantId, scanJobId);
        var handoff = AttackGraphHandoff.From(tenantId, scanJobId, candidates ?? []);

        // ---- Stage 3: retrieve, once per agent (SEC-23) -----------------------------------
        // SEC-48: the corpus version is collected from the chunks themselves as they come back,
        // so the audit records what actually answered rather than what settings predicted.
        var byRole = new Dictionary<AgentRole, IReadOnlyList<string>>();
        var corpusVersions = new HashSet<string>(StringComparer.Ordinal);

        // The results themselves, not just the chunks taken from them. Grounding coverage is
        // computed from what each retrieval answered, and this loop was the only place that ever
        // saw it — RetrievalEvaluation existed as an assertable type with nothing outside the tests
        // assembling one.
        var retrieved = new List<RetrievalResult>();

        foreach (var role in RetrievingRoles)
            byRole[role] = await RetrieveAsync(findings, handoff, role, corpusVersions, retrieved, ct);

        var evaluation = RetrievalEvaluation.Of(retrieved);

        // The union, for the report's citations: a chunk cited by either agent is knowledge the
        // audit rests on, and the report does not care which of them fetched it.
        var knowledge = byRole.Values
            .SelectMany(chunks => chunks)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        // ---- Stage 4: debate --------------------------------------------------------------
        // Edges from the caller's real graph only — never from the seeder's fallback nodes,
        // which is what keeps "no graph stage ran yet" and "the graph stage ran and found no
        // edges" from being confused with each other.
        var brief = briefRenderer.Render(scanJobId, findings, nodes, byRole, graph is { Count: > 0 } ? edges : null);

        // Adjudication is an entitlement. Everything above this line still ran — the findings are
        // normalized, the graph is built, the corpus was queried — so a tenant without it gets a
        // real scan, minus the Red/Blue debate over it.
        //
        // The distinction matters more than it looks. A skipped debate is NOT a debate that found
        // nothing: DraftAudit.NotAdjudicated exists so the report says "nobody examined this"
        // rather than letting Converged == false fall through to ChainBroken and print a
        // refutation that no agent ever made.
        var plan = await entitlements.ForTenantAsync(tenantId, ct);

        var audit = plan.DebateEnabled
            ? await debate.RunAsync(brief, ct) with { CorpusVersion = CorpusVersionOf(corpusVersions) }
            : DraftAuditNotAdjudicated(plan.PlanId, CorpusVersionOf(corpusVersions));

        // ---- Stage 5: report --------------------------------------------------------------
        var report = reportBuilder.Build(
            audit, knowledge, tenantId, scanJobId, Collection, DateTime.UtcNow);

        // ---- Stage 6: retention (SEC-35) --------------------------------------------------
        // The audit exists, so the customer's bundle has served its purpose and goes now — not
        // when somebody remembers to call the purge endpoint. Deleting by default is the whole
        // promise; making it a step of the pipeline rather than a follow-up call is what stops
        // "we delete your data" from depending on an operator's memory.
        var retentionOutcome = await retention.ApplyAfterAuditAsync(tenantId, scanJobId, report, ct);

        logger.LogInformation(
            "Thin slice for job {JobId}: {Findings} finding(s) -> {Nodes} node(s) -> "
            + "{Candidates} candidate chain(s) -> {Chunks} knowledge chunk(s) -> debate {Outcome} "
            + "in {Rounds} round(s) -> report with {Citations} citation(s); bundle purged, "
            + "report {Fate}",
            scanJobId, findings.Count, nodes.Count, handoff.Candidates.Count, knowledge.Count,
            audit.Outcome, audit.Rounds, report.Citations.Count,
            retentionOutcome.ReportRetained ? "retained" : "discarded");

        return new ThinSliceResult
        {
            Findings = findings,
            Nodes = nodes,
            Handoff = handoff,
            Knowledge = knowledge,
            Brief = brief,
            Audit = audit,
            Report = report,
            Retention = retentionOutcome,
            Evaluation = evaluation,
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
    /// <summary>
    /// The corpus version this run's citations rest on (SEC-48).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Empty when nothing was retrieved. An audit with no knowledge behind it should not name a
    /// corpus, because it did not use one — and a stamp taken from configuration would let it
    /// claim provenance it has not got.
    /// </para>
    /// <para>
    /// <b>More than one version is a real anomaly, so it is reported rather than resolved.</b> It
    /// means the collections were re-ingested while this scan was running, or that two corpora are
    /// mixed in one cluster. Picking the newest, or the most common, would produce a plausible
    /// single answer and hide the fact that the citations are not all from the same snapshot.
    /// </para>
    /// </remarks>
    private string CorpusVersionOf(IReadOnlyCollection<string> observed)
    {
        if (observed.Count == 0) return string.Empty;
        if (observed.Count == 1) return observed.First();

        var all = observed.OrderBy(v => v, StringComparer.Ordinal).ToList();

        logger.LogWarning(
            "Retrieval returned chunks from {Count} corpus versions ({Versions}). The collections "
            + "were re-ingested mid-scan, or two corpora share this cluster; the audit records all "
            + "of them rather than picking one", all.Count, string.Join(", ", all));

        return string.Join(", ", all);
    }

    private async Task<IReadOnlyList<string>> RetrieveAsync(
        IReadOnlyList<Finding> findings, AttackGraphHandoff handoff, AgentRole role,
        HashSet<string> corpusVersions, List<RetrievalResult> retrieved, CancellationToken ct)
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
            retrieved.Add(result);

            foreach (var chunk in result.Chunks)
            {
                if (!string.IsNullOrWhiteSpace(chunk.CorpusVersion))
                    corpusVersions.Add(chunk.CorpusVersion);

                var text = $"[{chunk.ChunkId}] {chunk.Text}";
                if (!chunks.Contains(text, StringComparer.Ordinal))
                    chunks.Add(text);
            }
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

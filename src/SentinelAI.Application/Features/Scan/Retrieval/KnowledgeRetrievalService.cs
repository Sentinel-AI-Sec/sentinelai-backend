using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// SEC-22: the retrieval decision tree. One flow, three modes, one mandatory rule.
/// </summary>
/// <remarks>
/// <para>
/// Matching a finding to knowledge is a decision tree, not a single search, and the presence or
/// absence of a clean identifier decides the path (<c>PIPELINE_A_CONTEXT.md</c> §4):
/// </para>
/// <code>
/// finding arrives
///    |
///    +- has a clean CVE or CWE id?
///    |     +- YES -> EXACT payload filter. No embedding. Deterministic.
///    |
///    +- no clean id, or exact returned nothing
///          +- build an NL query  (SEC-21)
///                +- embed with the SAME model as index time
///                      +- SEMANTIC search, ALWAYS source-filtered
///                            +- HYBRID refine: dense + sparse fused via RRF
/// </code>
/// <para>
/// <b>The tree is pure.</b> Qdrant is behind <see cref="IKnowledgeSearch"/> and the embedder
/// behind <see cref="IQueryEmbedder"/>, so every branch — including the CVE-misses-fall-back-to-
/// CWE arm, which is the one most likely to be wrong — is exercised by unit tests against an
/// in-memory corpus rather than only against a live cluster.
/// </para>
/// <para>
/// <b>What it does not do:</b> it does not build the query text (SEC-21's
/// <see cref="RetrievalQueryBuilder"/> does), does not decide which agent asks (SEC-23), does not
/// filter deprecated entries (SEC-24), and does not measure coverage (SEC-25). It records the
/// per-finding mode and the misses those stories need, and stops there.
/// </para>
/// </remarks>
public sealed class KnowledgeRetrievalService(
    RetrievalQueryBuilder queryBuilder,
    IKnowledgeSearch search,
    IQueryEmbedder embedder,
    ILogger<KnowledgeRetrievalService> logger) : IKnowledgeRetriever
{
    /// <summary>
    /// Grounds one finding, taking the first arm of the tree that answers.
    /// </summary>
    /// <param name="finding">A unified finding from SEC-16.</param>
    /// <param name="intent">What is being asked, which fixes the mandatory filter.</param>
    /// <param name="ct">Cancellation.</param>
    public async Task<RetrievalResult> RetrieveAsync(
        Finding finding, RetrievalIntent intent, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var collection = intent.Collection();
        var misses = new List<RetrievalMiss>();

        // The identifiers are read off the finding and validated here rather than parsed back out
        // of SEC-21's query string. An exact payload filter needs the id as a value, not as a
        // substring, and re-deriving it from prose would re-invent IdentifierFormats at the far
        // end of the seam.
        var cveId = IdentifierFormats.NormalizeCve(finding.CveId);
        var cweId = IdentifierFormats.NormalizeCwe(finding.CweId);

        // ---- Mode 1: exact ------------------------------------------------------------------
        // CVE then CWE, separately, because they are not interchangeable: the CVE is the specific
        // vulnerability and the CWE is its weakness class. Falling straight to semantic on a CVE
        // miss would throw away a weakness definition that is right there.
        if (cveId is not null)
        {
            var chunks = await search.ExactAsync(ExactLookup.ForCve(cveId, collection), ct);

            if (chunks.Count > 0)
                return new RetrievalResult(finding.Id, RetrievalMode.ExactFilter, chunks, misses);

            // §7: coverage is partial by design. Report it — a silent fallback reads downstream
            // as a direct hit on the specific CVE, which is a claim the audit cannot support.
            misses.Add(RetrievalMiss.CveNotInCorpus(cveId));

            logger.LogInformation(
                "{CveId} is not in the corpus; falling back to the weakness class for finding {FindingId}",
                cveId, finding.Id);
        }

        if (cweId is not null)
        {
            var chunks = await search.ExactAsync(ExactLookup.ForCwe(cweId, collection), ct);

            if (chunks.Count > 0)
                return new RetrievalResult(finding.Id, RetrievalMode.ExactFilter, chunks, misses);
        }

        if (cveId is null && cweId is null) misses.Add(RetrievalMiss.NoExactKey(finding.NodeRef));

        // ---- Modes 2 and 3: semantic, then hybrid where sparse exists -----------------------
        return await SearchAsync(finding, intent, misses, ct);
    }

    /// <summary>Grounds several findings, preserving input order.</summary>
    /// <remarks>
    /// Sequential rather than parallel. The corpus is a shared cluster and a scan can carry
    /// hundreds of findings; fanning them all out at once turns one scan into a load spike
    /// against a service every other scan is also using.
    /// </remarks>
    public async Task<IReadOnlyList<RetrievalResult>> RetrieveAllAsync(
        IEnumerable<Finding> findings, RetrievalIntent intent, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var results = new List<RetrievalResult>();
        foreach (var finding in findings)
            results.Add(await RetrieveAsync(finding, intent, ct));

        LogCoverage(results, intent);
        return results;
    }

    /// <summary>
    /// The meaning-based arm. Embeds SEC-21's query, then searches with the intent's mandatory
    /// filter.
    /// </summary>
    /// <remarks>
    /// The mode reported is <see cref="RetrievalMode.Hybrid"/> only when the embedder actually
    /// produced sparse weights. Reporting hybrid for a dense-only run would make SEC-25's "all
    /// three modes fire" assertion pass on a configuration where fusion never happened.
    /// </remarks>
    private async Task<RetrievalResult> SearchAsync(
        Finding finding, RetrievalIntent intent, List<RetrievalMiss> misses, CancellationToken ct)
    {
        var text = QueryTextFor(finding);

        if (text is null)
        {
            misses.Add(RetrievalMiss.Ungrounded(finding.NodeRef));
            return new RetrievalResult(finding.Id, RetrievalMode.None, [], misses);
        }

        var semantic = intent.ToQuery(text);

        // No model in this deployment. The exact arm above already ran and found nothing, so
        // this finding is genuinely ungrounded — but it is ungrounded for a reason worth naming,
        // not because the corpus lacks the knowledge. Reported rather than thrown: a scan must
        // not fail because one id-less finding could not be embedded.
        if (!embedder.IsAvailable)
        {
            misses.Add(RetrievalMiss.NoEmbedder(finding.NodeRef));

            logger.LogInformation(
                "No embedding model is configured, so finding {FindingId} ({NodeRef}) could not "
                + "be searched by meaning. Findings carrying a CVE or CWE are unaffected",
                finding.Id, finding.NodeRef);

            return new RetrievalResult(finding.Id, RetrievalMode.None, [], misses, semantic.Text);
        }

        var vectors = await embedder.EmbedAsync(semantic.Text, ct);

        var chunks = await search.SearchAsync(semantic, vectors, ct);
        var mode = vectors.SupportsHybrid ? RetrievalMode.Hybrid : RetrievalMode.Semantic;

        if (chunks.Count == 0)
        {
            misses.Add(RetrievalMiss.Ungrounded(finding.NodeRef));

            logger.LogWarning(
                "Finding {FindingId} ({NodeRef}) retrieved nothing from {Collection}; it will be "
                + "ungrounded in the audit", finding.Id, finding.NodeRef, semantic.Collection.Wire());

            return new RetrievalResult(finding.Id, RetrievalMode.None, [], misses, semantic.Text);
        }

        return new RetrievalResult(finding.Id, mode, chunks, misses, semantic.Text);
    }

    /// <summary>
    /// The text to embed: SEC-21's query, or a sanitised message when SEC-21 declines to build one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This fallback exists to reconcile two stories that disagree.</b>
    /// <see cref="RetrievalQueryBuilder.Build"/> returns null for a finding carrying neither a CWE
    /// nor a CVE, on the reasoning that with no id there is nothing the corpus can be keyed on.
    /// That is sound for the exact arm. It is the opposite of what SEC-22 is for:
    /// </para>
    /// <code>
    /// SEC-22, acceptance criterion 2:
    ///   "Given an infra finding WITHOUT AN ID, when retrieved, then the semantic path is
    ///    source-filtered to techniques/guidance, not flooded by CVEs."
    ///
    /// PIPELINE_A_CONTEXT.md §4:
    ///   "no clean id, or exact returned nothing -> build an NL query"
    /// </code>
    /// <para>
    /// Taking SEC-21's null literally would leave the semantic arm unreachable for exactly the
    /// findings it was written to serve, and the symptom would be a mode that simply never fires
    /// rather than an error. So the id-less case gets a query built from the cleaned message —
    /// the same sanitiser SEC-21's own stripping is tested against — and the finding is recorded
    /// as having had no exact key, which is the honest description of what happened.
    /// </para>
    /// <para>
    /// Null still means null: a finding whose message says nothing after cleaning has no question
    /// to ask, and is reported ungrounded rather than searched for with an empty string.
    /// </para>
    /// </remarks>
    private string? QueryTextFor(Finding finding)
    {
        if (queryBuilder.Build(finding) is { Length: > 0 } query) return query;

        var cleaned = QueryTextSanitizer.Clean(finding.Message);

        return cleaned.Length > 0 ? cleaned : null;
    }

    /// <summary>
    /// Logs grounding coverage and per-mode counts.
    /// </summary>
    /// <remarks>
    /// SEC-25 turns this into an asserted metric. Logging it now costs nothing and means a run
    /// that grounds two findings out of forty says so, rather than looking identical to a healthy
    /// one until somebody reads the report.
    /// </remarks>
    private void LogCoverage(IReadOnlyList<RetrievalResult> results, RetrievalIntent intent)
    {
        if (results.Count == 0) return;

        var grounded = results.Count(r => r.IsGrounded);
        var byMode = results.GroupBy(r => r.Mode).ToDictionary(g => g.Key, g => g.Count());

        logger.LogInformation(
            "Retrieval ({Intent}): {Grounded}/{Total} finding(s) grounded — exact {Exact}, "
            + "hybrid {Hybrid}, semantic {Semantic}, none {None}; {Fallbacks} fell back to the "
            + "weakness class",
            intent, grounded, results.Count,
            byMode.GetValueOrDefault(RetrievalMode.ExactFilter),
            byMode.GetValueOrDefault(RetrievalMode.Hybrid),
            byMode.GetValueOrDefault(RetrievalMode.Semantic),
            byMode.GetValueOrDefault(RetrievalMode.None),
            results.Count(r => r.FellBackToWeaknessClass));
    }
}

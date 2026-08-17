namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>Which arm of the decision tree actually answered.</summary>
/// <remarks>
/// Recorded per finding rather than inferred, because SEC-25 measures per-mode fire rates on the
/// fixture and asserts all three modes exercise. A mode that never fires is either dead code or
/// a tree that stopped branching, and neither shows up in a grounding-coverage number.
/// </remarks>
public enum RetrievalMode
{
    /// <summary>Nothing was retrieved. The finding is ungrounded and must be reported as such.</summary>
    None,

    /// <summary>Mode 1 — exact payload filter, no vectors. Deterministic.</summary>
    ExactFilter,

    /// <summary>Mode 2 — source-filtered dense search.</summary>
    Semantic,

    /// <summary>Mode 3 — dense + sparse fused with Reciprocal Rank Fusion.</summary>
    Hybrid,
}

/// <summary>
/// One chunk of the knowledge corpus, as retrieval returns it.
/// </summary>
/// <param name="ChunkId">The citation key. Stable and indexed — this is what a report cites.</param>
/// <param name="Source">Which canonical corpus it came from.</param>
/// <param name="Title">The chunk's own title.</param>
/// <param name="Text">The chunk body — clean prose, already stripped of CVSS vectors and markup at ingest.</param>
/// <param name="Score">The similarity or fusion score. Zero on an exact filter, which does not rank.</param>
/// <param name="CorpusVersion">Which corpus snapshot this chunk came from.</param>
/// <param name="CveId">Present on NVD chunks.</param>
/// <param name="CweId">Present on CWE chunks and on CVEs tagged with a weakness.</param>
/// <param name="CapecIds">From a CWE's <c>Related_Attack_Patterns</c>. <b>Unordered</b> — see remarks.</param>
/// <param name="TechniqueId">Present on ATT&amp;CK chunks.</param>
/// <param name="Status">
/// The source's own lifecycle value — <c>Draft</c>, <c>Stable</c>, <c>Incomplete</c>,
/// <c>Usable</c>. Null on ATT&amp;CK, NVD and OWASP chunks, which carry no such field.
/// </param>
/// <remarks>
/// <para>
/// <see cref="Score"/> is zero for <see cref="RetrievalMode.ExactFilter"/> because a payload
/// filter does not rank — it matches. Reporting a fabricated 1.0 there would make an exact hit
/// and a strong semantic hit indistinguishable downstream.
/// </para>
/// <para>
/// <b><see cref="CapecIds"/> is unordered.</b> It comes straight from MITRE's
/// <c>Related_Attack_Patterns</c>, and the first entry is not the most relevant: for CWE-284 it
/// is CAPEC-19 "Embedding Scripts within Scripts", a weak fit for an IAM misconfiguration
/// (<c>PIPELINE_A_CONTEXT.md</c> §7). Anything that picks one must rank them deliberately.
/// </para>
/// <para>
/// <b><see cref="Status"/> is read but never filtered on server-side.</b> It is a payload field
/// and not an indexed one, and the cluster answers a filter on it with HTTP 400 rather than a
/// slow scan. That is why SEC-24 is an over-fetch-and-filter over results instead of another
/// condition on the query — see <see cref="ChunkQuality"/>.
/// </para>
/// </remarks>
public sealed record KnowledgeChunk(
    string ChunkId,
    KnowledgeSource Source,
    string Title,
    string Text,
    float Score,
    string? CorpusVersion = null,
    string? CveId = null,
    string? CweId = null,
    IReadOnlyList<string>? CapecIds = null,
    string? TechniqueId = null,
    string? Status = null);

/// <summary>
/// Why a finding was not grounded as specifically as it could have been.
/// </summary>
/// <remarks>
/// <c>PIPELINE_A_CONTEXT.md</c> §7: "CVE coverage is partial by design. If a finding's CVE is not
/// in the corpus, fall back to retrieving its CWE chunk. The specific description is lost but the
/// weakness class, CAPEC links and technique survive — the finding stays grounded, less
/// specifically. <b>Report the miss rather than hiding it.</b>"
/// <para>
/// This type is that report. A fallback that is invisible looks exactly like a direct hit, and
/// the audit then claims specificity it does not have.
/// </para>
/// </remarks>
public sealed record RetrievalMiss(string Identifier, string Reason)
{
    /// <summary>The CVE was well-formed but is outside the corpus's deliberate NVD slice.</summary>
    public static RetrievalMiss CveNotInCorpus(string cveId) => new(
        cveId,
        "not in the corpus — the NVD slice covers the NuGet advisory ecosystem plus CVSS >= 9.0 "
        + "from 2022 onward; fell back to the weakness class");

    /// <summary>Neither identifier resolved, so the finding was answered by meaning alone.</summary>
    public static RetrievalMiss NoExactKey(string nodeRef) => new(
        nodeRef, "carried no clean CVE or CWE, so it was answered semantically rather than exactly");

    /// <summary>
    /// There is no embedding model, so the meaning-based arms could not run.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="Ungrounded"/> on purpose: this says the corpus was never asked,
    /// which is a deployment gap someone can close. "Ungrounded" says it was asked and had
    /// nothing, which is a corpus gap. Collapsing the two would hide which one you have.
    /// </remarks>
    public static RetrievalMiss NoEmbedder(string nodeRef) => new(
        nodeRef,
        "carried no clean identifier and no embedding model is configured, so it could not be "
        + "searched by meaning");

    /// <summary>Nothing at all came back. The finding is ungrounded.</summary>
    public static RetrievalMiss Ungrounded(string nodeRef) => new(
        nodeRef, "retrieved no knowledge; any assertion about it would be unsupported");

    /// <summary>
    /// Chunks came back and SEC-24 rejected every one of them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Deliberately not folded into <see cref="Ungrounded"/>, which says the corpus was asked and
    /// had nothing. This says the corpus had something and it was retired or empty — a stale
    /// corpus, fixed by re-running Pipeline A, versus a genuine knowledge gap, which no re-ingest
    /// closes. The two look identical from a coverage number and have nothing in common.
    /// </para>
    /// <para>
    /// It should never appear against a corpus Pipeline A built: its loaders drop these entries
    /// before they are ever embedded. Seeing it is the signal that they did not.
    /// </para>
    /// </remarks>
    public static RetrievalMiss NothingUsable(string identifier, int dropped) => new(
        identifier,
        $"matched {dropped} chunk(s), all deprecated or below the corpus's minimum useful length, "
        + "so none was used as grounding");
}

/// <summary>
/// What retrieval found for one finding, and how it found it.
/// </summary>
/// <param name="FindingId">The finding this grounds.</param>
/// <param name="Mode">Which arm answered.</param>
/// <param name="Chunks">The retrieved knowledge, best first.</param>
/// <param name="Misses">What was looked for and not found. Empty on a clean direct hit.</param>
/// <param name="Query">What was actually asked, for the trace. Null on a pure exact lookup.</param>
public sealed record RetrievalResult(
    Guid FindingId,
    RetrievalMode Mode,
    IReadOnlyList<KnowledgeChunk> Chunks,
    IReadOnlyList<RetrievalMiss> Misses,
    string? Query = null)
{
    /// <summary>True when this finding has knowledge behind it. SEC-25's coverage numerator.</summary>
    public bool IsGrounded => Chunks.Count > 0;

    /// <summary>True when the specific CVE was missed and the weakness class answered instead.</summary>
    public bool FellBackToWeaknessClass =>
        Mode == RetrievalMode.ExactFilter && Misses.Any(m => m.Reason.StartsWith("not in the corpus", StringComparison.Ordinal));
}

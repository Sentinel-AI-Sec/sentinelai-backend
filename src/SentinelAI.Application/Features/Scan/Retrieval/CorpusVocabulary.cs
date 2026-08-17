namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// Which Qdrant collection a query runs against (SEC-09).
/// </summary>
/// <remarks>
/// A chunk routed <c>both</c> is stored in each, so these are two views of one corpus rather
/// than two corpora. SEC-23 decides which agent reads which; SEC-22 only needs to name them.
/// </remarks>
public enum KnowledgeCollection
{
    /// <summary>28,950 points. Attacker knowledge — ATT&amp;CK techniques, CAPEC patterns, CVEs.</summary>
    Offense,

    /// <summary>31,179 points. Defender knowledge — detections, mitigations, OWASP guidance, CVEs.</summary>
    Defense,
}

/// <summary>
/// The <c>source</c> payload field: which canonical corpus a chunk came from.
/// </summary>
/// <remarks>
/// <b>Routing is per field, not per source.</b> ATT&amp;CK contributes to <em>both</em>
/// collections — technique descriptions to offense, detection analytics and mitigations to
/// defense. "ATT&amp;CK = offense" is the assumption <c>PIPELINE_A_CONTEXT.md</c> §2 warns
/// against by name.
/// </remarks>
public enum KnowledgeSource
{
    /// <summary>26,283 CVE description chunks. Sliced deliberately — see <c>PIPELINE_A_CONTEXT.md</c> §2.</summary>
    Nvd,

    /// <summary>944 weakness descriptions + 671 mitigations. The fallback when a CVE misses.</summary>
    Cwe,

    /// <summary>697 technique descriptions, 1,758 detections, 44 mitigations.</summary>
    Attack,

    /// <summary>556 attack patterns, 837 mitigations, 470 prerequisites.</summary>
    Capec,

    /// <summary>172 guidance chunks. The smallest source, and the one an unfiltered query buries.</summary>
    Owasp,
}

/// <summary>
/// The <c>content_type</c> payload field: which <em>kind</em> of text a chunk holds.
/// </summary>
/// <remarks>
/// This is the filter that separates "what is this weakness" from "how do I fix it".
/// <c>PIPELINE_A_CONTEXT.md</c> §4 measured the difference on the live corpus: the query
/// "how should I remediate unsafe deserialization" against defense returns NVD 4 / CWE 1
/// unfiltered — mostly CVE descriptions, not remediation — and CWE 2 / CAPEC 3 with
/// <c>content_type=mitigation</c>, which is actual guidance.
/// </remarks>
public enum KnowledgeContentType
{
    Description,
    Mitigation,
    Detection,
    Prerequisite,
    Guidance,
}

/// <summary>
/// The wire spellings of the corpus payload vocabulary.
/// </summary>
/// <remarks>
/// <para>
/// <b>These strings are written by Pipeline A and read by Pipeline B, in two different
/// languages.</b> They are the values actually stored in Qdrant payloads by
/// <c>sentinelai_knowledge</c>, so changing one here does not rename anything — it stops
/// matching, and a filter that matches nothing returns zero chunks rather than an error. Same
/// reasoning as <c>NodeTypeExtensions.Prefix</c>: cross-repo strings live in one switch instead
/// of scattered literals.
/// </para>
/// <para>
/// Source values are upper-case and content types are lower-case because that is how the
/// loaders wrote them. The asymmetry is theirs, not a slip here.
/// </para>
/// </remarks>
public static class CorpusWire
{
    /// <summary>The Qdrant collection name.</summary>
    public static string Wire(this KnowledgeCollection collection) => collection switch
    {
        KnowledgeCollection.Offense => "offense",
        KnowledgeCollection.Defense => "defense",
        _ => throw new ArgumentOutOfRangeException(
            nameof(collection), collection, "No collection name defined."),
    };

    /// <summary>The <c>source</c> payload value.</summary>
    public static string Wire(this KnowledgeSource source) => source switch
    {
        KnowledgeSource.Nvd => "NVD",
        KnowledgeSource.Cwe => "CWE",
        KnowledgeSource.Attack => "ATTACK",
        KnowledgeSource.Capec => "CAPEC",
        KnowledgeSource.Owasp => "OWASP",
        _ => throw new ArgumentOutOfRangeException(nameof(source), source, "No source value defined."),
    };

    /// <summary>The <c>content_type</c> payload value.</summary>
    public static string Wire(this KnowledgeContentType contentType) => contentType switch
    {
        KnowledgeContentType.Description => "description",
        KnowledgeContentType.Mitigation => "mitigation",
        KnowledgeContentType.Detection => "detection",
        KnowledgeContentType.Prerequisite => "prerequisite",
        KnowledgeContentType.Guidance => "guidance",
        _ => throw new ArgumentOutOfRangeException(
            nameof(contentType), contentType, "No content type value defined."),
    };

    /// <summary>Reads a <c>source</c> payload value back. Case-insensitive.</summary>
    public static bool TryReadSource(string? value, out KnowledgeSource source)
    {
        foreach (var candidate in Enum.GetValues<KnowledgeSource>())
        {
            if (string.Equals(candidate.Wire(), value, StringComparison.OrdinalIgnoreCase))
            {
                source = candidate;
                return true;
            }
        }

        source = default;
        return false;
    }
}

/// <summary>
/// The payload field names a filter may key on.
/// </summary>
/// <remarks>
/// <b>Only these are indexed.</b> Filtering on any other field returns HTTP 400 from Qdrant, not
/// a slow scan — <c>PIPELINE_A_CONTEXT.md</c> §3 says that is deliberate. Naming them here means
/// a filter is built from a constant rather than a literal, so a typo is a compile error instead
/// of a 400 at scan time.
/// </remarks>
public static class CorpusFields
{
    public const string ChunkId = "chunk_id";
    public const string CveId = "cve_id";
    public const string CweId = "cwe_id";
    public const string CapecId = "capec_id";
    public const string TechniqueId = "technique_id";
    public const string Source = "source";
    public const string Severity = "severity";
    public const string PublishedYear = "published_year";
    public const string Routing = "routing";
    public const string ContentType = "content_type";
    public const string OwaspId = "owasp_id";
    public const string MitigationId = "mitigation_id";

    /// <summary>Payload fields that carry text rather than being filterable keys.</summary>
    public const string Title = "title";
    public const string Text = "text";
    public const string CorpusVersion = "corpus_version";

    /// <summary>
    /// The source's lifecycle value. Read, never filtered on — it is <b>not</b> in
    /// <see cref="Indexed"/>.
    /// </summary>
    /// <remarks>
    /// Measured against the live corpus: <c>points/count</c> filtered on <c>status</c> returns
    /// HTTP 400 for every value on both collections. Present on CWE and CAPEC chunks only;
    /// ATT&amp;CK, NVD and OWASP points have no such key. SEC-24 reads it off the payload and
    /// filters client-side because the server will not do it.
    /// </remarks>
    public const string Status = "status";

    /// <summary>Every field a filter may key on, for the guard that rejects the rest.</summary>
    public static readonly IReadOnlySet<string> Indexed = new HashSet<string>(StringComparer.Ordinal)
    {
        ChunkId, CveId, CweId, CapecId, TechniqueId, Source,
        Severity, PublishedYear, Routing, ContentType, OwaspId, MitigationId,
    };
}

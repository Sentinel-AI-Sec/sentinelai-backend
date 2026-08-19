namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// Mode 1 of the retrieval decision tree: an exact payload filter, no vectors involved.
/// </summary>
/// <remarks>
/// <para>
/// <b>There is no public constructor, and that is the whole design of this type.</b> The
/// <c>source</c> condition is not optional, and the only way to build a lookup is through a
/// factory that supplies it. <c>PIPELINE_A_CONTEXT.md</c> §4 measured what omitting it costs:
/// </para>
/// <code>
/// cwe_id=CWE-502 alone          -> 825 points, top 3 are NVD CVEs
/// cwe_id=CWE-502 + source=CWE   -> 2 points, the actual definition
/// </code>
/// <para>
/// The 825 are mostly CVEs merely <em>tagged</em> with that CWE, not the weakness definition.
/// The document calls that failure "the single most dangerous bug shape in this system", because
/// it returns something confident and irrelevant while grounding coverage reports 100%. A
/// convention would not have caught it; a private constructor does.
/// </para>
/// </remarks>
public sealed record ExactLookup
{
    private ExactLookup(string field, string value, KnowledgeSource source, KnowledgeCollection collection)
    {
        Field = field;
        Value = value;
        Source = source;
        Collection = collection;
    }

    /// <summary>The indexed payload field to match on — always one of <see cref="CorpusFields"/>.</summary>
    public string Field { get; }

    /// <summary>The corpus-form identifier, e.g. <c>CVE-2024-21907</c>.</summary>
    public string Value { get; }

    /// <summary>The mandatory second condition. Never null, by construction.</summary>
    public KnowledgeSource Source { get; }

    public KnowledgeCollection Collection { get; }

    /// <summary>
    /// The CVE's own NVD record.
    /// </summary>
    /// <exception cref="ArgumentException">The id is not in the corpus's CVE form.</exception>
    /// <remarks>
    /// Validated through <see cref="IdentifierFormats"/> rather than trusted: a malformed id
    /// matches nothing, and "no results" is indistinguishable from "the corpus does not have it",
    /// so the two failures would be reported as the same thing.
    /// </remarks>
    public static ExactLookup ForCve(string cveId, KnowledgeCollection collection)
    {
        var canonical = IdentifierFormats.NormalizeCve(cveId)
            ?? throw new ArgumentException($"'{cveId}' is not a CVE identifier the corpus indexed.", nameof(cveId));

        return new ExactLookup(CorpusFields.CveId, canonical, KnowledgeSource.Nvd, collection);
    }

    /// <summary>
    /// The CWE's own weakness definition — not the CVEs tagged with it.
    /// </summary>
    /// <exception cref="ArgumentException">The id is not in the corpus's CWE form.</exception>
    public static ExactLookup ForCwe(string cweId, KnowledgeCollection collection)
    {
        var canonical = IdentifierFormats.NormalizeCwe(cweId)
            ?? throw new ArgumentException($"'{cweId}' is not a CWE identifier the corpus indexed.", nameof(cweId));

        return new ExactLookup(CorpusFields.CweId, canonical, KnowledgeSource.Cwe, collection);
    }

    public override string ToString() =>
        $"{Field}={Value} + {CorpusFields.Source}={Source.Wire()} in {Collection.Wire()}";
}

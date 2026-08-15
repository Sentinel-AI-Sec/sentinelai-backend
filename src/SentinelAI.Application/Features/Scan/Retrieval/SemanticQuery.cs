namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// Modes 2 and 3 of the decision tree: a meaning-based search, always narrowed before it is
/// ranked.
/// </summary>
/// <param name="Text">The natural-language query SEC-21 built. Embedded, never filtered on.</param>
/// <param name="Collection">Which collection to search.</param>
/// <param name="Sources">Restrict to these <c>source</c> values. Empty means "no source filter".</param>
/// <param name="ContentTypes">Restrict to these <c>content_type</c> values. Empty means none.</param>
/// <param name="TopK">How many chunks to return.</param>
/// <remarks>
/// <para>
/// <b>The constructor refuses a query with no filter at all.</b> Source-filtering the semantic
/// path is mandatory, and it is mandatory for a measured reason rather than a stylistic one —
/// with 26,283 NVD chunks against 172 OWASP chunks, an unfiltered semantic query returns CVEs
/// whatever it was asked. <c>PIPELINE_A_CONTEXT.md</c> §4 is explicit that this is a ranking
/// problem, not an ingest gap: the OWASP guidance is present, it is simply outnumbered 150 to 1.
/// </para>
/// <para>
/// Either kind of filter satisfies the rule. "Restrict to ATT&amp;CK and CAPEC" and "restrict to
/// mitigations" both cut the CVE bulk out of the candidate set, which is the property that
/// matters; requiring specifically a source filter would rule out the defense-side mitigation
/// query the same document recommends.
/// </para>
/// </remarks>
public sealed record SemanticQuery
{
    /// <summary>The default result count, matching the reference implementation's <c>top_k=10</c>.</summary>
    public const int DefaultTopK = 10;

    /// <exception cref="ArgumentException">
    /// The text is blank, or neither a source nor a content-type filter was supplied.
    /// </exception>
    public SemanticQuery(
        string text,
        KnowledgeCollection collection,
        IReadOnlyList<KnowledgeSource>? sources = null,
        IReadOnlyList<KnowledgeContentType>? contentTypes = null,
        int topK = DefaultTopK)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(topK);

        Sources = sources ?? [];
        ContentTypes = contentTypes ?? [];

        if (Sources.Count == 0 && ContentTypes.Count == 0)
        {
            throw new ArgumentException(
                "A semantic query must carry a source or content_type filter. Unfiltered, the "
                + "corpus's 26,283 NVD chunks outrank its 172 OWASP chunks for every query "
                + "(PIPELINE_A_CONTEXT.md §4), so the result is CVEs regardless of what was asked.",
                nameof(sources));
        }

        Text = text.Trim();
        Collection = collection;
        TopK = topK;
    }

    public string Text { get; }
    public KnowledgeCollection Collection { get; }
    public IReadOnlyList<KnowledgeSource> Sources { get; }
    public IReadOnlyList<KnowledgeContentType> ContentTypes { get; }
    public int TopK { get; }

    /// <summary>True when this query narrows the candidate set at all — always true here.</summary>
    public bool IsFiltered => Sources.Count > 0 || ContentTypes.Count > 0;

    public override string ToString()
    {
        var filters = new List<string>();
        if (Sources.Count > 0) filters.Add($"source in ({string.Join(", ", Sources.Select(s => s.Wire()))})");
        if (ContentTypes.Count > 0) filters.Add($"content_type in ({string.Join(", ", ContentTypes.Select(c => c.Wire()))})");

        return $"\"{Text}\" [{Collection.Wire()}, {string.Join(" and ", filters)}, top {TopK}]";
    }
}

/// <summary>
/// What a query embedder produced for one piece of text.
/// </summary>
/// <param name="Dense">The dense vector. 1024 floats under BGE-M3.</param>
/// <param name="Sparse">The lexical weights, or null when the embedder has no sparse output.</param>
/// <remarks>
/// <see cref="Sparse"/> being nullable is what implements the reference implementation's
/// degradation rule: <c>search_hybrid</c> falls back to dense-only when the embedder produced no
/// sparse indices — the Azure path, where <c>text-embedding-3-large</c> has no lexical half.
/// Modelling it as null rather than as an empty vector means the search adapter cannot
/// accidentally send an empty sparse prefetch, which matches nothing and silently halves recall.
/// </remarks>
public sealed record QueryVectors(IReadOnlyList<float> Dense, SparseQueryVector? Sparse)
{
    /// <summary>True when a hybrid search is possible for this text.</summary>
    public bool SupportsHybrid => Sparse is { Indices.Count: > 0 };
}

/// <summary>
/// BGE-M3's lexical half: term indices and their weights.
/// </summary>
/// <param name="Indices">Vocabulary positions with a non-zero weight.</param>
/// <param name="Values">The weight at each index. Same length as <paramref name="Indices"/>.</param>
/// <remarks>
/// Sparse is what catches rare literal tokens a dense embedding blurs — a package name, a
/// version, an ARN. It is why hybrid is the default for natural-language queries even though
/// dense alone usually looks fine on hand-written examples.
/// </remarks>
public sealed record SparseQueryVector(IReadOnlyList<uint> Indices, IReadOnlyList<float> Values)
{
    /// <exception cref="ArgumentException">The two arrays disagree on length.</exception>
    public static SparseQueryVector Create(IReadOnlyList<uint> indices, IReadOnlyList<float> values)
    {
        ArgumentNullException.ThrowIfNull(indices);
        ArgumentNullException.ThrowIfNull(values);

        if (indices.Count != values.Count)
        {
            throw new ArgumentException(
                $"A sparse vector needs one value per index; got {indices.Count} index/indices and "
                + $"{values.Count} value(s).", nameof(values));
        }

        return new SparseQueryVector(indices, values);
    }
}

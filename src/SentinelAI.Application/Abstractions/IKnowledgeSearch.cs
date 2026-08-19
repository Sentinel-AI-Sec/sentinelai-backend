using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Application.Abstractions;

/// <summary>
/// The corpus, as the decision tree needs to ask it (SEC-22). Application says WHAT; the Qdrant
/// adapter in Infrastructure says HOW.
/// </summary>
/// <remarks>
/// <para>
/// Two operations, not three, because "semantic" and "hybrid" are the same request with and
/// without a sparse vector. The reference implementation makes the same call:
/// <c>search_hybrid</c> delegates to <c>search_dense</c> when the embedder produced no sparse
/// indices. Splitting them into two methods would give the caller a decision it cannot make —
/// only the embedder knows whether sparse exists.
/// </para>
/// <para>
/// The signature deliberately mirrors <c>sentinelai_knowledge/validate.py</c>'s
/// <c>(collection, query, top_k, flt)</c>, as <c>PIPELINE_A_CONTEXT.md</c> §8 asks, so the shape
/// that has already been validated against the live corpus is the shape this side implements.
/// </para>
/// </remarks>
public interface IKnowledgeSearch
{
    /// <summary>
    /// Mode 1: an exact payload filter. No embedding, no ranking, deterministic.
    /// </summary>
    /// <remarks>
    /// Returns every match, which for a well-formed lookup is a handful — the CWE-502 definition
    /// is two chunks. It is the <see cref="ExactLookup"/> type, not this method, that guarantees
    /// the mandatory <c>source</c> condition is present.
    /// </remarks>
    Task<IReadOnlyList<KnowledgeChunk>> ExactAsync(ExactLookup lookup, CancellationToken ct = default);

    /// <summary>
    /// Modes 2 and 3: filter, then rank by vector similarity.
    /// </summary>
    /// <param name="query">Carries the mandatory filter — see <see cref="SemanticQuery"/>.</param>
    /// <param name="vectors">Dense always; sparse when the embedder has a lexical half, in which
    /// case the adapter must prefetch both and fuse with RRF.</param>
    Task<IReadOnlyList<KnowledgeChunk>> SearchAsync(
        SemanticQuery query, QueryVectors vectors, CancellationToken ct = default);
}

/// <summary>
/// Turns a query string into vectors comparable with the ones the corpus was indexed with.
/// </summary>
/// <remarks>
/// <para>
/// <b>The same-model invariant lives here.</b> <c>PIPELINE_A_CONTEXT.md</c> §5: "The model that
/// indexed the corpus must be the model that queries it. Different models produce numbers that
/// mean different things, so comparing them gives meaningless results <em>and no error
/// appears</em>." That last clause is why <see cref="Model"/> and <see cref="Revision"/> are on
/// the interface rather than being an implementation detail — something has to be able to
/// compare them against the corpus manifest and refuse to start, and it cannot do that if the
/// embedder will not say what it is.
/// </para>
/// <para>
/// The corpus in use was indexed with <c>BAAI/bge-m3</c> at revision
/// <c>5617a9f61b028005a4858fdac845db406aefb181</c>, 1024-dimensional float32 dense plus native
/// sparse. SEC-48 asserts the match at the A-to-B boundary.
/// </para>
/// </remarks>
public interface IQueryEmbedder
{
    /// <summary>The model identifier, e.g. <c>BAAI/bge-m3</c>.</summary>
    string Model { get; }

    /// <summary>The pinned revision. A model name alone does not pin the weights.</summary>
    string Revision { get; }

    /// <summary>Dense dimensionality, so a mismatch with the collection is caught before a query runs.</summary>
    int DenseDimensions { get; }

    /// <summary>
    /// False when this deployment has no embedding model available.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The exact-filter arm of the decision tree needs no model at all — looking up
    /// <c>CWE-502</c> by its id is a payload filter. So a corpus with no embedder is a perfectly
    /// usable configuration: identifier-carrying findings ground for real, and only the
    /// meaning-based arms are unavailable.
    /// </para>
    /// <para>
    /// This exists so the retrieval service can report that as an honest miss rather than
    /// discovering it by catching an exception mid-scan. Asking beforehand is the difference
    /// between "this finding could not be grounded semantically" and a failed scan.
    /// </para>
    /// </remarks>
    bool IsAvailable { get; }

    /// <summary>
    /// Embeds one query string.
    /// </summary>
    /// <remarks>
    /// Only query text is ever embedded. The scanned repository is never indexed — that is the
    /// two-pipeline separation, and it holds by construction because there is no other embedding
    /// entry point on this side.
    /// </remarks>
    Task<QueryVectors> EmbedAsync(string text, CancellationToken ct = default);
}

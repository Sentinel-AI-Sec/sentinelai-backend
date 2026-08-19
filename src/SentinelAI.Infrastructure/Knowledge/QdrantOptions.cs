namespace SentinelAI.Infrastructure.Knowledge;

/// <summary>
/// Where the knowledge corpus lives and which snapshot of it this deployment expects.
/// </summary>
/// <remarks>
/// Bound from the <c>Knowledge</c> configuration section. The corpus is produced by a different
/// repository on a different schedule, so everything here is deployment configuration rather
/// than something the backend can derive.
/// </remarks>
public sealed class QdrantOptions
{
    public const string SectionName = "Knowledge";

    /// <summary>gRPC endpoint, e.g. <c>http://localhost:6334</c>.</summary>
    /// <remarks>
    /// Port 6334, not 6333. The .NET client speaks gRPC; 6333 is the REST port and connecting to
    /// it produces a protocol error rather than a helpful message.
    /// </remarks>
    public string Endpoint { get; set; } = "http://localhost:6334";

    /// <summary>API key for a managed cluster. Empty for a local container.</summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>
    /// How many chunks to over-fetch per vector before fusion.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The reference implementation prefetches <c>top_k * 4</c> from each of dense and sparse
    /// before Reciprocal Rank Fusion picks the final <c>top_k</c>. Fusing two lists of exactly
    /// <c>k</c> gives RRF almost nothing to reorder; the multiplier is what makes fusion do work.
    /// </para>
    /// <para>
    /// <b>It is not the headroom SEC-24 needs, despite the shape.</b> This widens the two
    /// <em>inputs</em> to fusion, and fusion still emits exactly <c>limit</c> points — so after it
    /// runs there are <c>k</c>, and dropping any leaves fewer than <c>k</c>. The dense-only path
    /// settles the question: it has no prefetch at all and asks for <c>limit</c> directly. SEC-24
    /// therefore raises the outer limit itself, via <c>ChunkQuality.OverFetch</c>, and the two
    /// multiply — at the defaults, 10 wanted → 20 requested → 80 prefetched per vector.
    /// </para>
    /// </remarks>
    public int PrefetchMultiplier { get; set; } = 4;

    /// <summary>
    /// Fail startup when the collection's dense vector size disagrees with the embedder's.
    /// </summary>
    /// <remarks>
    /// The cheap half of the same-model invariant. It cannot prove the same model was used — two
    /// different 1024-dimensional models pass — but a dimension mismatch is the one form of the
    /// error that is free to detect, and it is otherwise silent: Qdrant rejects the query at
    /// search time, per finding, deep inside a scan.
    /// </remarks>
    public bool VerifyDimensionsOnStartup { get; set; } = true;
}

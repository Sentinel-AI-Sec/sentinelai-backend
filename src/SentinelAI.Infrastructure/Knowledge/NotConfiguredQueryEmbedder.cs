using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Infrastructure.Knowledge;

/// <summary>
/// The default <see cref="IQueryEmbedder"/>: it refuses to embed, loudly, and says what has to be
/// decided before it can be replaced.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a throwing default rather than a working stub.</b> A stub embedder returning arbitrary
/// vectors would make every semantic query return the same near-random chunks, and the debate
/// would cite them. That is the silent-fallback failure <c>PIPELINE_A_CONTEXT.md</c> §5 exists to
/// prevent, in the direction the document warns about: "comparing them gives meaningless results
/// <em>and no error appears</em>." A stub here would manufacture exactly that.
/// </para>
/// <para>
/// <b>The exact-filter arm still works.</b> Mode 1 uses no vectors at all, so a deployment with no
/// embedder configured still grounds every finding that carries a clean CVE or CWE — which on the
/// fixture is most of them. Only the semantic and hybrid arms are unavailable, and they fail
/// naming the reason rather than degrading.
/// </para>
/// <para>
/// Replacing this is a registration change. The open decision is which adapter: an HTTP call to
/// the <c>sentinelai-knowledge</c> BGE-M3 service (preserves the same-model invariant against the
/// current corpus, and is the only option that yields sparse vectors), or Azure
/// <c>text-embedding-3-large</c> (the AID-01 production target, dense-only, and requiring Pipeline
/// A to be re-run so the corpus is indexed with the same model).
/// </para>
/// </remarks>
public sealed class NotConfiguredQueryEmbedder : IQueryEmbedder
{
    public string Model => "none";
    public string Revision => "none";

    /// <summary>
    /// BGE-M3's width, which is what the current corpus was indexed at.
    /// </summary>
    /// <remarks>
    /// Reported rather than zero so <c>QdrantKnowledgeSearch.VerifyCompatibleAsync</c> still
    /// checks something useful at startup: a corpus that is not 1024-dimensional is a corpus this
    /// backend could not query even once an embedder is wired, and that is worth knowing before
    /// the embedder decision rather than after.
    /// </remarks>
    public int DenseDimensions => 1024;

    /// <summary>
    /// False. The exact-filter arm is unaffected and still grounds every finding carrying a
    /// clean CVE or CWE; only the meaning-based arms are unavailable, and retrieval reports that
    /// per finding rather than throwing.
    /// </summary>
    public bool IsAvailable => false;

    public Task<QueryVectors> EmbedAsync(string text, CancellationToken ct = default) =>
        throw new InvalidOperationException(
            "No query embedder is configured, so the semantic and hybrid retrieval arms cannot "
            + "run. The exact-filter arm is unaffected and still grounds findings that carry a "
            + "clean CVE or CWE. To enable the rest, register an IQueryEmbedder that uses the same "
            + "model the corpus was indexed with — BAAI/bge-m3 @ 5617a9f61b028005a4858fdac845db406aefb181, "
            + "1024-dim dense plus native sparse. A different model produces vectors that are not "
            + "comparable with the index, which yields confident, meaningless results and no error.");
}

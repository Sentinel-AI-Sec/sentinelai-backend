using SentinelAI.Application.Abstractions;

namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// What Pipeline A published about the corpus it built (SEC-48).
/// </summary>
/// <remarks>
/// <para>
/// The corpus is produced by a different repository, on a different machine, on its own schedule.
/// Everything the query side needs in order to prove it matches the corpus has to travel with it,
/// and this is that record — <c>sentinelai-knowledge</c> writes it as
/// <c>out/corpus_manifest.json</c> at the end of an ingest.
/// </para>
/// <para>
/// <b>Why a manifest rather than configuration.</b> Both ends already carry a configured model
/// name and revision, and two configured constants agreeing proves only that somebody typed the
/// same thing twice. The manifest is written by the process that actually did the embedding, so
/// comparing against it compares against what happened rather than what was intended.
/// </para>
/// </remarks>
public sealed record CorpusManifest
{
    /// <summary>The snapshot identifier, e.g. <c>2026-08-10-1143</c>.</summary>
    public required string CorpusVersion { get; init; }

    /// <summary>The model that embedded the corpus, e.g. <c>BAAI/bge-m3</c>.</summary>
    public required string Model { get; init; }

    /// <summary>
    /// The pinned weights. Null when the ingest did not record one.
    /// </summary>
    /// <remarks>
    /// <b>A model name alone does not pin weights.</b> <c>BAAI/bge-m3</c> today and
    /// <c>BAAI/bge-m3</c> after an upstream re-release are the same name over different numbers,
    /// and every similarity score computed across that boundary is quietly wrong. That is why an
    /// absent revision is reported rather than treated as a pass.
    /// </remarks>
    public string? Revision { get; init; }

    /// <summary>Dense width the collections were created with.</summary>
    public required int DenseDimensions { get; init; }

    /// <summary>Whether the ingest produced sparse vectors, which is what makes hybrid possible.</summary>
    public bool Sparse { get; init; } = true;

    /// <summary>
    /// Vector norms from the ingest's own <c>parity_check()</c>, over a fixed probe list.
    /// </summary>
    /// <remarks>
    /// The strongest available evidence that two ends run the same model, because it compares
    /// numbers the model produced rather than strings a human typed. Empty when the ingest
    /// recorded no baseline.
    /// </remarks>
    public IReadOnlyList<double> ParityNorms { get; init; } = [];

    /// <summary>True when the manifest pins the weights, not merely the model name.</summary>
    public bool HasPinnedRevision => !string.IsNullOrWhiteSpace(Revision);

    /// <summary>True when the manifest carries numbers the query side can reproduce.</summary>
    public bool HasParityBaseline => ParityNorms.Count > 0;
}

/// <summary>What disagrees between the corpus and the embedder about to query it.</summary>
public enum CorpusMismatchKind
{
    /// <summary>Different model names. Every score across this boundary is meaningless.</summary>
    Model,

    /// <summary>Same name, different pinned weights.</summary>
    Revision,

    /// <summary>Different dense widths. Qdrant rejects the query outright.</summary>
    Dimensions,

    /// <summary>The manifest names a model but pins no revision, so nothing can be proven.</summary>
    RevisionNotPinned,

    /// <summary>The manifest carries no parity baseline, so only identifiers were compared.</summary>
    NoParityBaseline,
}

/// <summary>One way a corpus and an embedder fail to be the same pairing.</summary>
/// <param name="Kind">Which check failed.</param>
/// <param name="Explanation">What to tell whoever has to fix it.</param>
/// <param name="IsFatal">
/// True when continuing would produce confident, meaningless results. False when the pairing is
/// merely unproven rather than known-wrong.
/// </param>
public sealed record CorpusMismatch(CorpusMismatchKind Kind, string Explanation, bool IsFatal);

/// <summary>
/// SEC-48: the same-model invariant, enforced at the A-to-B boundary rather than documented.
/// </summary>
/// <remarks>
/// <para>
/// <c>PIPELINE_A_CONTEXT.md</c> §5: "The model that indexed the corpus must be the model that
/// queries it. Different models produce numbers that mean different things, so comparing them
/// gives meaningless results <b>and no error appears</b>." That last clause is the entire reason
/// this type exists — nothing downstream can detect the failure, so it must be caught before a
/// query is ever issued.
/// </para>
/// <para>
/// <b>Pure, and therefore testable without a cluster or a 2.2 GB model.</b> It compares a manifest
/// against whatever an <see cref="IQueryEmbedder"/> says it is. The numeric half of the proof —
/// reproducing the ingest's parity norms — needs a live service and lives in
/// <c>HttpQueryEmbedder.VerifyParityAsync</c>. This decides what must be checked and how loudly to
/// complain, which is the half worth unit-testing.
/// </para>
/// <para>
/// <b>Fatal versus unproven is the distinction that matters.</b> A revision mismatch is known-wrong
/// and must stop the boot. A manifest with no revision recorded is not wrong — it is unproven, and
/// reporting that as a pass would be the same silent failure wearing a different coat.
/// </para>
/// </remarks>
public static class CorpusParity
{
    /// <summary>Every way this embedder and this corpus disagree. Empty means fully proven.</summary>
    public static IReadOnlyList<CorpusMismatch> Check(CorpusManifest manifest, IQueryEmbedder embedder)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(embedder);

        var found = new List<CorpusMismatch>();

        if (!string.Equals(manifest.Model, embedder.Model, StringComparison.OrdinalIgnoreCase))
        {
            found.Add(new CorpusMismatch(
                CorpusMismatchKind.Model,
                $"The corpus was embedded with '{manifest.Model}' but this deployment queries with "
                + $"'{embedder.Model}'. Vectors from two models are not comparable, and similarity "
                + "scores across them are meaningless without erroring.",
                IsFatal: true));
        }

        if (manifest.DenseDimensions != embedder.DenseDimensions)
        {
            found.Add(new CorpusMismatch(
                CorpusMismatchKind.Dimensions,
                $"The corpus stores {manifest.DenseDimensions}-dimensional vectors and the embedder "
                + $"produces {embedder.DenseDimensions}.",
                IsFatal: true));
        }

        if (!manifest.HasPinnedRevision)
        {
            found.Add(new CorpusMismatch(
                CorpusMismatchKind.RevisionNotPinned,
                $"The manifest for corpus '{manifest.CorpusVersion}' names '{manifest.Model}' but "
                + "records no revision, so a matching name is all that could be checked. An "
                + "upstream re-release under the same name would pass this.",
                IsFatal: false));
        }
        else if (!string.Equals(manifest.Revision, embedder.Revision, StringComparison.OrdinalIgnoreCase))
        {
            found.Add(new CorpusMismatch(
                CorpusMismatchKind.Revision,
                $"The corpus was embedded at revision '{manifest.Revision}' and this deployment "
                + $"queries at '{embedder.Revision}'. Same model name, different weights.",
                IsFatal: true));
        }

        if (!manifest.HasParityBaseline)
        {
            found.Add(new CorpusMismatch(
                CorpusMismatchKind.NoParityBaseline,
                $"Corpus '{manifest.CorpusVersion}' published no parity norms, so the boundary was "
                + "verified by comparing identifiers rather than by reproducing numbers. Run the "
                + "ingest's parity_check() and publish it to close that gap.",
                IsFatal: false));
        }

        return found;
    }
}

/// <summary>Reading a set of mismatches without re-deriving what they mean at each call site.</summary>
public static class CorpusParityResults
{
    /// <summary>The mismatches that must stop a boot or a scan.</summary>
    public static IReadOnlyList<CorpusMismatch> Fatal(this IReadOnlyList<CorpusMismatch> mismatches) =>
        [.. mismatches.Where(m => m.IsFatal)];

    /// <summary>
    /// True when nothing is known to be wrong. Weaker than <see cref="IsFullyProven"/>.
    /// </summary>
    /// <remarks>
    /// Deliberately distinct: a corpus with no recorded revision is usable and unproven at the
    /// same time, and collapsing the two would let the weaker state report itself as the stronger.
    /// </remarks>
    public static bool IsUsable(this IReadOnlyList<CorpusMismatch> mismatches) =>
        !mismatches.Any(m => m.IsFatal);

    /// <summary>True when every check passed, including the ones that only warn.</summary>
    public static bool IsFullyProven(this IReadOnlyList<CorpusMismatch> mismatches) =>
        mismatches.Count == 0;

    /// <summary>A one-line summary for a log or a failure message.</summary>
    public static string Describe(this IReadOnlyList<CorpusMismatch> mismatches) =>
        mismatches.Count == 0
            ? "corpus and embedder agree on model, revision and dimensions, with a parity baseline"
            : string.Join(" ", mismatches.Select(m => $"[{m.Kind}] {m.Explanation}"));
}

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Infrastructure.Knowledge;

/// <summary>
/// SEC-48: refuses to retrieve against a corpus this deployment cannot prove it matches.
/// </summary>
/// <remarks>
/// <para>
/// The invariant is stated in <c>PIPELINE_A_CONTEXT.md</c> §5 and, until this story, only stated:
/// the model that indexed the corpus must be the model that queries it, and a mismatch "gives
/// meaningless results <b>and no error appears</b>". Documentation cannot enforce that. This can.
/// </para>
/// <para>
/// <b>Three outcomes, deliberately not two.</b>
/// </para>
/// <list type="table">
/// <item>
///   <term>Proven</term>
///   <description>Manifest and embedder agree on model, revision and dimensions, and the corpus
///   published a parity baseline. Logged once, at information.</description>
/// </item>
/// <item>
///   <term>Unproven</term>
///   <description>Nothing is known to be wrong, but something could not be checked — usually no
///   manifest, or a manifest with no pinned revision. The host runs. The log says exactly which
///   check was skipped, because "unverified" reported as "verified" is the failure this story
///   exists to prevent.</description>
/// </item>
/// <item>
///   <term>Known-wrong</term>
///   <description>A real mismatch. Fatal by default: every semantic result would be confident and
///   meaningless, and nothing downstream can detect it.</description>
/// </item>
/// </list>
/// <para>
/// <b>Why an explicit guard rather than folding it into the readiness service.</b>
/// <see cref="KnowledgeReadinessService"/> wakes a possibly-sleeping HTTP service and reproduces
/// its numbers; this compares two descriptions and needs no network at all. Keeping them apart
/// means the cheap half still runs on a deployment with no embedding service — which is most of
/// them — instead of being skipped along with the expensive half.
/// </para>
/// </remarks>
public sealed class CorpusBoundaryGuard(
    ICorpusManifestSource manifests,
    IQueryEmbedder embedder,
    IOptions<CorpusManifestOptions> options,
    ILogger<CorpusBoundaryGuard> logger)
{
    /// <summary>
    /// Checks the boundary. Throws when the pairing is known-wrong and fail-fast is on.
    /// </summary>
    /// <returns>Every mismatch found, fatal or not. Empty means fully proven.</returns>
    /// <exception cref="InvalidOperationException">
    /// The corpus and the embedder are a mismatched pair.
    /// </exception>
    public async Task<IReadOnlyList<CorpusMismatch>> VerifyAsync(CancellationToken ct = default)
    {
        var manifest = await manifests.GetAsync(ct);

        if (manifest is null)
        {
            logger.LogWarning(
                "The A-to-B boundary is unverified: no corpus manifest is available, so this "
                + "deployment cannot show that {Model} @ {Revision} is what built the corpus it is "
                + "about to query", embedder.Model, embedder.Revision);

            return [];
        }

        var mismatches = CorpusParity.Check(manifest, embedder);
        var fatal = mismatches.Fatal();

        if (fatal.Count > 0)
        {
            var message =
                $"Corpus '{manifest.CorpusVersion}' and this deployment's embedder are not the "
                + $"same pairing. {fatal.Describe()} "
                + "Retrieval would return confident, meaningless results, so startup has been "
                + "stopped. Set Knowledge:Manifest:FailFastOnMismatch to false only if you know "
                + "why the mismatch is safe.";

            if (options.Value.FailFastOnMismatch) throw new InvalidOperationException(message);

            logger.LogError("{Message}", message);
            return mismatches;
        }

        if (mismatches.Count > 0)
        {
            logger.LogWarning(
                "Corpus '{Version}' is usable but not fully proven: {Detail}",
                manifest.CorpusVersion, mismatches.Describe());

            return mismatches;
        }

        logger.LogInformation(
            "A-to-B boundary verified: corpus '{Version}' was built by {Model} @ {Revision} "
            + "({Dim}-dim), which is what this deployment queries with",
            manifest.CorpusVersion, manifest.Model, manifest.Revision, manifest.DenseDimensions);

        return mismatches;
    }
}

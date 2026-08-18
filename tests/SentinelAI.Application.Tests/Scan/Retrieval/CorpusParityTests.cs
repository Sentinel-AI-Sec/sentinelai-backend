using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// SEC-48's first acceptance criterion: retrieval uses the identical embedder that built the
/// corpus, enforced at the boundary rather than documented.
/// </summary>
/// <remarks>
/// <para>
/// The failure being prevented has no symptom. <c>PIPELINE_A_CONTEXT.md</c> §5: different models
/// "give meaningless results <b>and no error appears</b>". So the tests that matter most here are
/// the ones asserting a mismatch is <em>caught</em>, and the ones asserting an unproven pairing is
/// not reported as a verified one.
/// </para>
/// <para>
/// The corpus in use was built by <c>BAAI/bge-m3</c> at revision
/// <c>5617a9f6…</c>, 1024-dimensional — those are the real values, so a test that passes here is
/// describing the real deployment.
/// </para>
/// </remarks>
public class CorpusParityTests
{
    private const string Model = "BAAI/bge-m3";
    private const string Revision = "5617a9f61b028005a4858fdac845db406aefb181";

    private static CorpusManifest Manifest(
        string model = Model,
        string? revision = Revision,
        int dims = 1024,
        double[]? norms = null) => new()
        {
            CorpusVersion = "2026-08-10-1143",
            Model = model,
            Revision = revision,
            DenseDimensions = dims,
            ParityNorms = norms ?? [17.4821, 19.2033, 18.0577],
        };

    private sealed class Embedder(
        string model = Model, string revision = Revision, int dims = 1024) : IQueryEmbedder
    {
        public string Model { get; } = model;
        public string Revision { get; } = revision;
        public int DenseDimensions { get; } = dims;
        public bool IsAvailable => true;

        public Task<QueryVectors> EmbedAsync(string text, CancellationToken ct = default) =>
            throw new NotSupportedException("parity checking never embeds");
    }

    // ---- the acceptance criterion -------------------------------------------------------------

    [Fact]
    public void A_matching_corpus_and_embedder_are_fully_proven()
    {
        var mismatches = CorpusParity.Check(Manifest(), new Embedder());

        Assert.True(mismatches.IsFullyProven());
        Assert.True(mismatches.IsUsable());
        Assert.Empty(mismatches);
    }

    [Fact]
    public void A_different_model_is_fatal()
    {
        var mismatches = CorpusParity.Check(
            Manifest(model: "intfloat/e5-large-v2"), new Embedder());

        Assert.False(mismatches.IsUsable());
        Assert.Contains(mismatches, m => m.Kind == CorpusMismatchKind.Model && m.IsFatal);
    }

    /// <summary>
    /// The one a dimension check cannot catch: same name, same width, different weights.
    /// </summary>
    /// <remarks>
    /// This is why <see cref="CorpusManifest.Revision"/> exists at all. An upstream re-release
    /// under an unchanged name produces vectors of the right shape and the wrong meaning, and
    /// <c>QdrantKnowledgeSearch.VerifyCompatibleAsync</c> — which compares widths — passes it.
    /// </remarks>
    [Fact]
    public void A_different_revision_of_the_same_model_is_fatal()
    {
        var mismatches = CorpusParity.Check(
            Manifest(revision: "0000000000000000000000000000000000000000"), new Embedder());

        Assert.False(mismatches.IsUsable());

        var found = Assert.Single(mismatches, m => m.Kind == CorpusMismatchKind.Revision);
        Assert.True(found.IsFatal);
        Assert.Contains("different weights", found.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void A_different_dense_width_is_fatal()
    {
        var mismatches = CorpusParity.Check(Manifest(dims: 768), new Embedder());

        Assert.False(mismatches.IsUsable());
        Assert.Contains(mismatches, m => m.Kind == CorpusMismatchKind.Dimensions && m.IsFatal);
    }

    [Fact]
    public void Model_comparison_ignores_case_because_registries_do()
    {
        var mismatches = CorpusParity.Check(Manifest(model: "baai/BGE-m3"), new Embedder());

        Assert.DoesNotContain(mismatches, m => m.Kind == CorpusMismatchKind.Model);
    }

    // ---- unproven is not the same as wrong, and must not read as verified ----------------------

    /// <summary>
    /// A manifest with no revision is usable and unproven at once, and the difference is the whole
    /// point of the story.
    /// </summary>
    [Fact]
    public void A_manifest_with_no_revision_is_usable_but_not_proven()
    {
        var mismatches = CorpusParity.Check(Manifest(revision: null), new Embedder());

        Assert.True(mismatches.IsUsable());          // nothing is known to be wrong
        Assert.False(mismatches.IsFullyProven());    // and nothing has been proven either

        var found = Assert.Single(mismatches, m => m.Kind == CorpusMismatchKind.RevisionNotPinned);
        Assert.False(found.IsFatal);
    }

    [Fact]
    public void A_manifest_with_no_parity_baseline_says_only_identifiers_were_compared()
    {
        var mismatches = CorpusParity.Check(Manifest(norms: []), new Embedder());

        Assert.True(mismatches.IsUsable());
        Assert.False(mismatches.IsFullyProven());

        var found = Assert.Single(mismatches, m => m.Kind == CorpusMismatchKind.NoParityBaseline);
        Assert.False(found.IsFatal);
        Assert.Contains("comparing identifiers", found.Explanation, StringComparison.Ordinal);
    }

    /// <summary>
    /// An unpinned revision must never be silently satisfied by the embedder's own revision.
    /// </summary>
    /// <remarks>
    /// The tempting implementation treats a null manifest revision as "matches anything", which
    /// makes the strongest check disappear exactly when the corpus is least documented.
    /// </remarks>
    [Fact]
    public void An_absent_manifest_revision_is_never_treated_as_a_match()
    {
        var mismatches = CorpusParity.Check(Manifest(revision: null), new Embedder());

        Assert.DoesNotContain(mismatches, m => m.Kind == CorpusMismatchKind.Revision);
        Assert.Contains(mismatches, m => m.Kind == CorpusMismatchKind.RevisionNotPinned);
    }

    // ---- reporting -----------------------------------------------------------------------------

    [Fact]
    public void Several_things_can_be_wrong_at_once_and_all_are_reported()
    {
        var mismatches = CorpusParity.Check(
            Manifest(model: "other/model", dims: 768, revision: null, norms: []),
            new Embedder());

        Assert.Equal(4, mismatches.Count);
        Assert.Equal(2, mismatches.Fatal().Count);   // model + dimensions
    }

    [Fact]
    public void The_description_of_a_clean_boundary_says_what_was_actually_checked()
    {
        var clean = CorpusParity.Check(Manifest(), new Embedder()).Describe();

        Assert.Contains("model, revision and dimensions", clean, StringComparison.Ordinal);
        Assert.Contains("parity baseline", clean, StringComparison.Ordinal);
    }

    [Fact]
    public void A_failure_description_names_both_sides_so_it_can_be_acted_on()
    {
        var described = CorpusParity.Check(
            Manifest(model: "intfloat/e5-large-v2"), new Embedder()).Describe();

        Assert.Contains("intfloat/e5-large-v2", described, StringComparison.Ordinal);
        Assert.Contains(Model, described, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Null_arguments_are_rejected_rather_than_passing_vacuously(bool nullManifest)
    {
        Assert.Throws<ArgumentNullException>(() => nullManifest
            ? CorpusParity.Check(null!, new Embedder())
            : CorpusParity.Check(Manifest(), null!));
    }
}

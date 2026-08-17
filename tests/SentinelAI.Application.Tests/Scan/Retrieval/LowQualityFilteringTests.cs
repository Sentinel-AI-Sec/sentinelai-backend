using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// SEC-24 through the decision tree: the guard is on every path from the corpus to the debate,
/// and the over-fetch in front of it is what keeps <c>k</c> results coming back.
/// </summary>
/// <remarks>
/// <see cref="ChunkQualityTests"/> proves the policy. These prove it is actually reached — on the
/// semantic arm, on the exact arm, and with the arithmetic wired up rather than merely available.
/// </remarks>
public class LowQualityFilteringTests
{
    private static (KnowledgeRetrievalService Service, FakeCorpus Corpus) Build(bool stale = true)
    {
        var corpus = new FakeCorpus(withLowQuality: stale);

        var service = new KnowledgeRetrievalService(
            new RetrievalQueryBuilder(), corpus, new FakeEmbedder(),
            NullLogger<KnowledgeRetrievalService>.Instance);

        return (service, corpus);
    }

    /// <summary>A finding with no identifier, so the semantic arm answers it.</summary>
    private static Domain.Models.Finding Deserialization()
    {
        var finding = FindingFixture.Code();
        finding.CweId = null;
        finding.CveId = null;
        finding.Message = FakeCorpus.DeserializationQuery;

        return finding;
    }

    // ---- the acceptance criterion ------------------------------------------------------------
    // "Given retrieval results, when filtered, then DEPRECATED entries are removed and k results
    //  remain."

    [Fact]
    public async Task Deprecated_entries_are_removed_and_k_results_remain()
    {
        var (service, _) = Build();

        var result = await service.RetrieveAsync(Deserialization(), RetrievalIntent.HowAnAttackerWould);

        // Nine rejects sit above every live chunk in this corpus. All nine are gone, and the list
        // is still full — the over-fetch replaced them rather than leaving a short answer.
        Assert.Equal(SemanticQuery.DefaultTopK, result.Chunks.Count);
        Assert.All(result.Chunks, c => Assert.True(ChunkQuality.IsUsable(c), $"{c.ChunkId} should have been dropped"));
    }

    [Fact]
    public async Task None_of_the_three_deprecation_signals_survives_into_the_results()
    {
        var (service, _) = Build();

        var result = await service.RetrieveAsync(Deserialization(), RetrievalIntent.HowAnAttackerWould);

        // status flag — CAPEC and CWE
        Assert.DoesNotContain(result.Chunks, c => ChunkQuality.DeadStatuses.Contains(c.Status ?? ""));

        // title marker — the only signal ATT&CK has
        Assert.DoesNotContain(result.Chunks,
            c => c.Title.StartsWith("DEPRECATED", StringComparison.OrdinalIgnoreCase));

        // thin text — the low-quality half of the story
        Assert.DoesNotContain(result.Chunks, c => c.Text.Trim().Length < ChunkQuality.MinimumUsefulCharacters);
    }

    /// <summary>
    /// The over-fetch is the story, so it is asserted rather than inferred from the result count.
    /// </summary>
    [Fact]
    public async Task The_corpus_is_asked_for_more_than_the_caller_wants_back()
    {
        var (service, corpus) = Build();

        var result = await service.RetrieveAsync(Deserialization(), RetrievalIntent.HowAnAttackerWould);

        var (query, _) = Assert.Single(corpus.Searches);

        Assert.Equal(ChunkQuality.OverFetch(SemanticQuery.DefaultTopK), query.TopK);
        Assert.Equal(SemanticQuery.DefaultTopK, result.Chunks.Count);
    }

    /// <summary>
    /// What the same corpus returns if the request is not over-fetched — the measurement that
    /// makes the multiplier necessary rather than decorative.
    /// </summary>
    [Fact]
    public async Task Asking_for_only_k_would_have_returned_almost_nothing()
    {
        var (_, corpus) = Build();

        var atK = RetrievalIntent.HowAnAttackerWould.ToQuery(
            FakeCorpus.DeserializationQuery, SemanticQuery.DefaultTopK);

        var vectors = await new FakeEmbedder().EmbedAsync(atK.Text);
        var survivors = ChunkQuality.Apply(await corpus.SearchAsync(atK, vectors), SemanticQuery.DefaultTopK);

        Assert.Equal(9, survivors.Dropped);
        Assert.Single(survivors.Chunks);
    }

    // ---- the exact arm -------------------------------------------------------------------------

    /// <summary>
    /// The guard covers mode 1 too, and a wholly-retired exact hit falls through instead of being
    /// returned as a confident, deterministic, top-ranked citation.
    /// </summary>
    [Fact]
    public async Task An_exact_hit_that_is_entirely_deprecated_is_not_returned()
    {
        var corpus = new RetiredWeaknessCorpus();

        var service = new KnowledgeRetrievalService(
            new RetrievalQueryBuilder(), corpus, new FakeEmbedder { IsAvailable = false },
            NullLogger<KnowledgeRetrievalService>.Instance);

        var finding = FindingFixture.Code();          // CWE-502, no CVE
        var result = await service.RetrieveAsync(finding, RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.None, result.Mode);
        Assert.Empty(result.Chunks);

        // And it says which of the two problems this is: a stale corpus, not a knowledge gap.
        Assert.Contains(result.Misses, m => m.Reason.Contains("all deprecated", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Misses, m => m.Reason.Contains("retrieved no knowledge", StringComparison.Ordinal));
    }

    /// <summary>
    /// A retired CVE record is not the same claim as a CVE outside the corpus's NVD slice.
    /// </summary>
    /// <remarks>
    /// The slice is partial by design (<c>PIPELINE_A_CONTEXT.md</c> §7) and "not in the corpus" is
    /// the honest report for that. It is the wrong report here: the record exists and has been
    /// withdrawn. Reporting both would also flip
    /// <see cref="RetrievalResult.FellBackToWeaknessClass"/> on for a fallback with a different
    /// cause, so the audit would explain itself incorrectly.
    /// </remarks>
    [Fact]
    public async Task A_retired_cve_record_is_not_reported_as_missing_from_the_corpus()
    {
        var corpus = new RetiredWeaknessCorpus();

        var service = new KnowledgeRetrievalService(
            new RetrievalQueryBuilder(), corpus, new FakeEmbedder { IsAvailable = false },
            NullLogger<KnowledgeRetrievalService>.Instance);

        var finding = FindingFixture.Dependency();     // CVE-2024-21907 + CWE-502
        var result = await service.RetrieveAsync(finding, RetrievalIntent.HowAnAttackerWould);

        Assert.Contains(result.Misses, m => m.Reason.Contains("all deprecated", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Misses, m => m.Reason.StartsWith("not in the corpus", StringComparison.Ordinal));
        Assert.False(result.FellBackToWeaknessClass);
    }

    // ---- a healthy corpus is untouched -----------------------------------------------------------

    /// <summary>
    /// The guard is belt and braces, and belt and braces has to be free. Pipeline A drops these
    /// entries at ingest and the live corpus has none, so on a clean corpus SEC-24 must change
    /// nothing at all.
    /// </summary>
    [Fact]
    public async Task A_clean_corpus_is_unaffected_by_the_guard()
    {
        var (service, _) = Build(stale: false);

        foreach (var finding in FindingFixture.All())
        {
            var result = await service.RetrieveAsync(finding, RetrievalIntent.HowAnAttackerWould);

            Assert.True(result.IsGrounded, $"{finding.NodeRef} lost its grounding to the quality filter");
            Assert.DoesNotContain(result.Misses, m => m.Reason.Contains("all deprecated", StringComparison.Ordinal));
        }
    }

    /// <summary>
    /// A corpus where every exact hit is retired — the stale corpus the guard exists for.
    /// </summary>
    /// <remarks>
    /// Deliberately minimal: the point is what the exact arm does when its answer is rot, not the
    /// ranking that <see cref="FakeCorpus"/> exercises. It answers whichever identifier was asked
    /// for so that "the record exists and is withdrawn" is what the test actually simulates,
    /// rather than a CWE chunk standing in for a CVE lookup.
    /// </remarks>
    private sealed class RetiredWeaknessCorpus : Application.Abstractions.IKnowledgeSearch
    {
        public Task<IReadOnlyList<KnowledgeChunk>> ExactAsync(ExactLookup lookup, CancellationToken ct = default)
        {
            var isCve = lookup.Field == CorpusFields.CveId;

            return Task.FromResult<IReadOnlyList<KnowledgeChunk>>(
            [
                new KnowledgeChunk(
                    ChunkId: isCve ? $"nvd-{lookup.Value.ToLowerInvariant()}" : lookup.Value.ToLowerInvariant(),
                    Source: lookup.Source,
                    Title: $"DEPRECATED: {lookup.Value}",
                    Text: "This entry has been deprecated and replaced by another.",
                    Score: 0f,
                    CveId: isCve ? lookup.Value : null,
                    CweId: isCve ? null : lookup.Value,
                    Status: "Deprecated"),
            ]);
        }

        public Task<IReadOnlyList<KnowledgeChunk>> SearchAsync(
            SemanticQuery query, QueryVectors vectors, CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<KnowledgeChunk>>([]);
    }
}

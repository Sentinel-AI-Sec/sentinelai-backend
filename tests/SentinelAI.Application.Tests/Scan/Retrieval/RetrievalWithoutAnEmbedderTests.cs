using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// The corpus-without-a-model deployment: identifier lookups work, meaning search does not, and
/// the difference is reported per finding rather than crashing the scan.
/// </summary>
/// <remarks>
/// This is a supported configuration, not a degraded one. Looking up CWE-502 by its id is a
/// payload filter with no vector in it, so a corpus alone grounds every finding that carries an
/// identifier — which on the fixture is most of them.
/// </remarks>
public class RetrievalWithoutAnEmbedderTests
{
    private static (KnowledgeRetrievalService Service, FakeCorpus Corpus) Build()
    {
        var corpus = new FakeCorpus();
        var service = new KnowledgeRetrievalService(
            new RetrievalQueryBuilder(), corpus, new FakeEmbedder { IsAvailable = false },
            NullLogger<KnowledgeRetrievalService>.Instance);

        return (service, corpus);
    }

    [Fact]
    public async Task A_finding_with_a_cwe_is_still_grounded_for_real()
    {
        var (service, corpus) = Build();

        var result = await service.RetrieveAsync(FindingFixture.Code(), RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.ExactFilter, result.Mode);
        Assert.True(result.IsGrounded);
        Assert.Contains(result.Chunks, c => c.ChunkId == "cwe-502");

        // No embedding was attempted, because none was needed.
        Assert.Empty(corpus.Searches);
    }

    [Fact]
    public async Task A_finding_with_no_identifier_reports_the_missing_model_rather_than_throwing()
    {
        var (service, corpus) = Build();

        var finding = FindingFixture.Infra();
        finding.CweId = null;
        finding.CveId = null;

        var result = await service.RetrieveAsync(finding, RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.None, result.Mode);
        Assert.False(result.IsGrounded);
        Assert.Contains(result.Misses, m => m.Reason.Contains("no embedding model", StringComparison.Ordinal));

        // The corpus was never asked, which is what distinguishes this from a corpus gap.
        Assert.Empty(corpus.Searches);
    }

    [Fact]
    public async Task A_whole_scan_completes_rather_than_failing_on_the_id_less_finding()
    {
        var (service, _) = Build();

        var results = await service.RetrieveAllAsync(FindingFixture.All(), RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(3, results.Count);
        Assert.All(results, r => Assert.True(r.IsGrounded));
    }
}

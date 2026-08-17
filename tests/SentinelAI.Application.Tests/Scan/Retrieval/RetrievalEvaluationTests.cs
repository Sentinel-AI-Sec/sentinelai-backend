using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// SEC-25: grounding coverage and per-mode fire rates, measured on the fixture.
/// </summary>
/// <remarks>
/// The acceptance criterion is one sentence — "coverage and per-mode counts are reported and all
/// three modes fire" — and the two halves fail differently. Coverage catches a corpus that cannot
/// answer; fire rates catch a tree that stopped branching, which coverage cannot see at all
/// because the arm that still works answers everything.
/// </remarks>
public class RetrievalEvaluationTests
{
    private static (KnowledgeRetrievalService Service, FakeCorpus Corpus) Build(bool withSparse = true)
    {
        var corpus = new FakeCorpus();

        var service = new KnowledgeRetrievalService(
            new RetrievalQueryBuilder(), corpus, new FakeEmbedder(withSparse),
            NullLogger<KnowledgeRetrievalService>.Instance);

        return (service, corpus);
    }

    /// <summary>A finding with neither identifier, so only the meaning-based arms can answer it.</summary>
    private static Domain.Models.Finding IdLess()
    {
        var finding = FindingFixture.Infra();
        finding.CweId = null;
        finding.CveId = null;

        return finding;
    }

    // ---- the acceptance criterion --------------------------------------------------------------
    // "Given the fixture findings, when retrieval runs, then grounding coverage and per-mode
    //  counts are reported and all three modes fire."

    [Fact]
    public async Task Every_fixture_finding_is_grounded()
    {
        var (service, _) = Build();

        var results = await service.RetrieveAllAsync(
            FindingFixture.All(), RetrievalIntent.HowAnAttackerWould);

        var evaluation = RetrievalEvaluation.Of(results);

        Assert.Equal(3, evaluation.Findings);
        Assert.Equal(3, evaluation.Grounded);
        Assert.Equal(100, evaluation.CoveragePercent);
        Assert.True(evaluation.FullyGrounded);
        Assert.Equal(0, evaluation.Ungrounded);
    }

    /// <summary>
    /// All three modes, which takes two configurations rather than one.
    /// </summary>
    /// <remarks>
    /// <b>Hybrid versus semantic is decided by the embedder, not by the finding.</b> A deployment
    /// whose model has no lexical half can never fire hybrid, however many findings it is given —
    /// so "all three modes fire" is a claim about a configuration, and proving it means measuring
    /// across more than one. That is why <see cref="RetrievalEvaluation.Of"/> takes results
    /// instead of running the retrieval itself.
    /// </remarks>
    [Fact]
    public async Task All_three_modes_fire_across_the_fixture()
    {
        var (hybridCapable, _) = Build(withSparse: true);
        var (denseOnly, _) = Build(withSparse: false);

        var withSparse = await hybridCapable.RetrieveAllAsync(
            [.. FindingFixture.All(), IdLess()], RetrievalIntent.HowAnAttackerWould);

        var withoutSparse = await denseOnly.RetrieveAllAsync(
            [IdLess()], RetrievalIntent.HowAnAttackerWould);

        var evaluation = RetrievalEvaluation.Of([.. withSparse, .. withoutSparse]);

        Assert.True(evaluation.AllModesFired, evaluation.Report());
        Assert.Empty(evaluation.ModesThatDidNotFire);

        Assert.True(evaluation.Count(RetrievalMode.ExactFilter) > 0);
        Assert.True(evaluation.Count(RetrievalMode.Hybrid) > 0);
        Assert.True(evaluation.Count(RetrievalMode.Semantic) > 0);
    }

    [Fact]
    public async Task The_numbers_are_reported_in_a_line_a_regression_is_visible_in()
    {
        var (service, _) = Build();

        var results = await service.RetrieveAllAsync(
            FindingFixture.All(), RetrievalIntent.HowAnAttackerWould);

        var report = RetrievalEvaluation.Of(results).Report();

        Assert.Contains("grounding coverage 3/3 (100%)", report, StringComparison.Ordinal);
        Assert.Contains("exact", report, StringComparison.Ordinal);
        Assert.Contains("semantic", report, StringComparison.Ordinal);
        Assert.Contains("hybrid", report, StringComparison.Ordinal);
    }

    // ---- what each half catches that the other cannot ---------------------------------------------

    /// <summary>
    /// The failure coverage alone cannot see: 100% grounded, and the semantic half never ran.
    /// </summary>
    /// <remarks>
    /// This is the case SEC-25 exists for. Every fixture finding carries a CWE, so the exact arm
    /// answers all of them and coverage reports a perfect score — while modes 2 and 3 sit
    /// untested, and the first id-less finding in production is the experiment.
    /// </remarks>
    [Fact]
    public async Task Full_coverage_does_not_mean_every_mode_was_exercised()
    {
        var (service, _) = Build();

        var results = await service.RetrieveAllAsync(
            FindingFixture.All(), RetrievalIntent.HowAnAttackerWould);

        var evaluation = RetrievalEvaluation.Of(results);

        Assert.True(evaluation.FullyGrounded);
        Assert.Equal(100, evaluation.CoveragePercent);

        // And yet:
        Assert.False(evaluation.AllModesFired);
        Assert.Contains(RetrievalMode.Semantic, evaluation.ModesThatDidNotFire);
        Assert.Contains(RetrievalMode.Hybrid, evaluation.ModesThatDidNotFire);
    }

    [Fact]
    public async Task An_ungrounded_finding_shows_up_in_coverage_and_is_named_in_the_report()
    {
        var (service, _) = Build();

        var unanswerable = FindingFixture.Infra();
        unanswerable.CweId = null;
        unanswerable.CveId = null;
        unanswerable.Message = "zzzz qqqq wwww";      // matches nothing in the corpus

        var results = await service.RetrieveAllAsync(
            [FindingFixture.Code(), unanswerable], RetrievalIntent.HowAnAttackerWould);

        var evaluation = RetrievalEvaluation.Of(results);

        Assert.Equal(2, evaluation.Findings);
        Assert.Equal(1, evaluation.Grounded);
        Assert.Equal(1, evaluation.Ungrounded);
        Assert.Equal(50, evaluation.CoveragePercent);
        Assert.False(evaluation.FullyGrounded);
        Assert.Equal(1, evaluation.Count(RetrievalMode.None));
    }

    /// <summary>
    /// The CVE fallback is invisible in coverage, so it is counted separately.
    /// </summary>
    /// <remarks>
    /// These findings are grounded — in the weakness class rather than the specific CVE
    /// (<c>PIPELINE_A_CONTEXT.md</c> §7, the NVD slice is partial by design). Coverage says 100%
    /// and is right; the audit is still less specific than it looks, and only this number says so.
    /// </remarks>
    [Fact]
    public async Task Weakness_class_fallbacks_are_counted_even_though_coverage_stays_perfect()
    {
        var (service, _) = Build();

        var finding = FindingFixture.Code();
        finding.CveId = "CVE-1999-0001";              // well-formed, outside the corpus slice
        finding.CweId = "CWE-502";

        var evaluation = RetrievalEvaluation.Of(
            await service.RetrieveAllAsync([finding], RetrievalIntent.HowAnAttackerWould));

        Assert.True(evaluation.FullyGrounded);
        Assert.Equal(1, evaluation.FellBackToWeaknessClass);
        Assert.Contains("1 fell back to the weakness class", evaluation.Report(), StringComparison.Ordinal);
    }

    // ---- the arithmetic ----------------------------------------------------------------------------

    [Fact]
    public void An_empty_run_is_complete_rather_than_a_total_failure()
    {
        // Every one of its zero findings is grounded. Scoring 0 would make the cleanest possible
        // scan trip a coverage threshold.
        var evaluation = RetrievalEvaluation.Of([]);

        Assert.Equal(1d, evaluation.GroundingCoverage);
        Assert.Equal(100, evaluation.CoveragePercent);
        Assert.True(evaluation.FullyGrounded);
    }

    [Fact]
    public void Coverage_is_truncated_so_a_single_ungrounded_finding_cannot_round_away()
    {
        var results = Enumerable.Range(0, 200)
            .Select(i => new RetrievalResult(
                Guid.NewGuid(),
                i == 0 ? RetrievalMode.None : RetrievalMode.ExactFilter,
                i == 0 ? [] : [Chunk()],
                []))
            .ToList();

        var evaluation = RetrievalEvaluation.Of(results);

        Assert.Equal(199, evaluation.Grounded);
        Assert.Equal(99, evaluation.CoveragePercent);   // not 100
        Assert.False(evaluation.FullyGrounded);
    }

    [Fact]
    public void Modes_are_counted_per_finding_not_per_chunk()
    {
        // One finding with five chunks and one with a single chunk are equally grounded. Averaging
        // chunk counts would let a rich result hide a thin one.
        var results = new List<RetrievalResult>
        {
            new(Guid.NewGuid(), RetrievalMode.ExactFilter, [Chunk(), Chunk(), Chunk(), Chunk(), Chunk()], []),
            new(Guid.NewGuid(), RetrievalMode.Hybrid, [Chunk()], []),
        };

        var evaluation = RetrievalEvaluation.Of(results);

        Assert.Equal(2, evaluation.Findings);
        Assert.Equal(2, evaluation.Grounded);
        Assert.Equal(1, evaluation.Count(RetrievalMode.ExactFilter));
        Assert.Equal(1, evaluation.Count(RetrievalMode.Hybrid));
    }

    [Fact]
    public void The_ungrounded_bucket_is_not_a_mode_that_can_fire()
    {
        // Otherwise "all modes fired" would be satisfiable by a run that grounded nothing.
        var results = Enumerable.Range(0, 5)
            .Select(_ => new RetrievalResult(Guid.NewGuid(), RetrievalMode.None, [], []))
            .ToList();

        var evaluation = RetrievalEvaluation.Of(results);

        Assert.False(evaluation.AllModesFired);
        Assert.Equal(3, evaluation.ModesThatDidNotFire.Count);
        Assert.DoesNotContain(RetrievalMode.None, evaluation.ModesThatDidNotFire);
    }

    [Fact]
    public void The_report_names_the_modes_that_never_fired()
    {
        var results = new List<RetrievalResult>
        {
            new(Guid.NewGuid(), RetrievalMode.ExactFilter, [Chunk()], []),
        };

        var report = RetrievalEvaluation.Of(results).Report();

        Assert.Contains("Modes that never fired: semantic, hybrid", report, StringComparison.Ordinal);
    }

    private static KnowledgeChunk Chunk() => new(
        "cwe-502", KnowledgeSource.Cwe, "CWE-502", "Deserialization of untrusted data.", 0.5f);
}

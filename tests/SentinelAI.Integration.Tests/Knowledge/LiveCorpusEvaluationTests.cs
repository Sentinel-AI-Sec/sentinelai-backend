using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Knowledge;

namespace SentinelAI.Integration.Tests.Knowledge;

/// <summary>
/// SEC-25 against the real corpus: what grounding coverage actually is, on real knowledge, in the
/// configuration this deployment runs.
/// </summary>
/// <remarks>
/// <para>
/// The unit tests measure the metric against an in-memory corpus, which proves the arithmetic.
/// This proves the number, and the number is the point of the story — "prove every finding is
/// backed by retrieved knowledge" is a claim about Pipeline A's 32,432 chunks, not about a fake.
/// </para>
/// <para>
/// <b>No embedder here, deliberately, and that is what makes the second test interesting.</b>
/// Level 3 of <c>Knowledge_Setup.md</c> is optional and usually absent, so this is the
/// configuration most developers and most CI runs actually have. In it the exact arm answers
/// every identifier-carrying finding and coverage is 100% — while two of the three modes never
/// run at all. A story that only measured coverage would call that a complete pass.
/// </para>
/// <para>
/// Read-only. Set <c>SENTINELAI_CORPUS_URL</c> / <c>SENTINELAI_CORPUS_KEY</c>, or configure
/// <c>Knowledge:Endpoint</c>, to run it.
/// </para>
/// </remarks>
public class LiveCorpusEvaluationTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private static KnowledgeRetrievalService Retriever()
    {
        var search = new QdrantKnowledgeSearch(
            Options.Create(new QdrantOptions
            {
                Endpoint = LiveCorpusFactAttribute.Url!,
                ApiKey = LocalDev.CorpusKey,
            }),
            NullLogger<QdrantKnowledgeSearch>.Instance);

        return new KnowledgeRetrievalService(
            new RetrievalQueryBuilder(), search, new NotConfiguredQueryEmbedder(),
            NullLogger<KnowledgeRetrievalService>.Instance);
    }

    private static Finding At(Layer layer, string cwe, string? cve, string node, string message) => new()
    {
        Id = Guid.CreateVersion7(),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = "fixture",
        Layer = layer,
        Severity = 4,
        CweId = cwe,
        CveId = cve,
        NodeRef = node,
        Message = message,
    };

    /// <summary>
    /// One finding per layer, each carrying the identifier its layer really produces.
    /// </summary>
    /// <remarks>
    /// Dependency findings carry a CVE, code findings a CWE from the rule-mapping table, infra
    /// findings a bare CWE and never a CVE (<c>PIPELINE_A_CONTEXT.md</c> §7). Measuring coverage
    /// over a set that was all one shape would prove only that one shape works.
    /// </remarks>
    private static IReadOnlyList<Finding> Fixture() =>
    [
        At(Layer.Dep, "CWE-502", "CVE-2024-21907", NodeId.Package("Newtonsoft.Json:9.0.1"),
            "Newtonsoft.Json 9.0.1 is vulnerable to improper handling of exceptional conditions."),

        At(Layer.Code, "CWE-502", null, NodeId.Code("src/OrderApp/OrderService.cs"),
            "Unsafe deserialization of untrusted data in OrderService."),

        At(Layer.Infra, "CWE-284", null, NodeId.Role("order-task-role"),
            "The IAM role policy grants s3:* on the customer data bucket."),

        At(Layer.Infra, "CWE-732", null, NodeId.Role("order-task-role"),
            "Incorrect permission assignment for a critical resource."),

        At(Layer.Code, "CWE-89", null, NodeId.Code("src/OrderApp/Reports.cs"),
            "SQL query built by string concatenation from request input."),
    ];

    /// <summary>
    /// The story's headline number, measured on real knowledge.
    /// </summary>
    [LiveCorpusFact]
    public async Task Every_fixture_finding_is_grounded_in_the_real_corpus()
    {
        var results = await Retriever().RetrieveAllAsync(Fixture(), RetrievalIntent.HowAnAttackerWould);

        var evaluation = RetrievalEvaluation.Of(results);

        Assert.Equal(5, evaluation.Findings);
        Assert.True(evaluation.FullyGrounded, $"not every finding was grounded — {evaluation.Report()}");
        Assert.Equal(100, evaluation.CoveragePercent);
    }

    /// <summary>
    /// Both halves of the corpus answer, so SEC-23's split holds on real knowledge too.
    /// </summary>
    [LiveCorpusFact]
    public async Task Coverage_holds_for_the_defensive_question_as_well_as_the_offensive_one()
    {
        var retriever = Retriever();

        var red = RetrievalEvaluation.Of(
            await retriever.RetrieveAllAsync(Fixture(), RetrievalIntent.HowAnAttackerWould));

        var blue = RetrievalEvaluation.Of(
            await retriever.RetrieveAllAsync(Fixture(), RetrievalIntent.HowToFix));

        Assert.True(red.FullyGrounded, $"offense: {red.Report()}");
        Assert.True(blue.FullyGrounded, $"defense: {blue.Report()}");
    }

    /// <summary>
    /// The honest half: 100% coverage, and two of the three modes never ran.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is SEC-25's actual argument, asserted rather than argued. Without the embedding
    /// service every one of these findings is answered by a payload filter — real grounding, in
    /// real corpus text, and a perfect coverage score — while modes 2 and 3 are untested by this
    /// run. The evaluation says so out loud instead of reporting a clean pass.
    /// </para>
    /// <para>
    /// If this test ever fails because a mode <em>did</em> fire, an embedder has been configured
    /// for the suite. That is good news and the assertion below is what will point it out.
    /// </para>
    /// </remarks>
    [LiveCorpusFact]
    public async Task Perfect_coverage_without_an_embedder_still_reports_two_modes_as_never_fired()
    {
        var evaluation = RetrievalEvaluation.Of(
            await Retriever().RetrieveAllAsync(Fixture(), RetrievalIntent.HowAnAttackerWould));

        Assert.Equal(100, evaluation.CoveragePercent);

        Assert.Equal(evaluation.Findings, evaluation.Count(RetrievalMode.ExactFilter));
        Assert.False(evaluation.AllModesFired);

        Assert.Equal(
            [RetrievalMode.Semantic, RetrievalMode.Hybrid],
            evaluation.ModesThatDidNotFire);

        Assert.Contains("Modes that never fired", evaluation.Report(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A CVE outside the corpus's deliberate NVD slice is grounded in its weakness class, and the
    /// evaluation counts that separately from a clean direct hit.
    /// </summary>
    [LiveCorpusFact]
    public async Task A_cve_outside_the_slice_is_counted_as_a_weakness_class_fallback()
    {
        var finding = At(Layer.Dep, "CWE-502", "CVE-1999-0001",
            NodeId.Package("ancient.package:0.0.1"), "A deliberately out-of-slice advisory.");

        var evaluation = RetrievalEvaluation.Of(
            await Retriever().RetrieveAllAsync([finding], RetrievalIntent.HowAnAttackerWould));

        Assert.True(evaluation.FullyGrounded);
        Assert.Equal(1, evaluation.FellBackToWeaknessClass);
    }
}

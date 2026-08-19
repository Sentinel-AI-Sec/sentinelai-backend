using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// SEC-22's decision tree. Each arm gets its own test, because each one closes a different
/// failure and a happy-path test would pass with any of them removed.
/// </summary>
public class KnowledgeRetrievalServiceTests
{

    private static (KnowledgeRetrievalService Service, FakeCorpus Corpus) Build(bool withSparse = true)
    {
        var corpus = new FakeCorpus();

        // SEC-21's real builder, not a stand-in: the point of the tree is what it does with the
        // query that story actually produces, including the null it returns for an id-less
        // finding (see KnowledgeRetrievalService.QueryTextFor).
        var service = new KnowledgeRetrievalService(
            new RetrievalQueryBuilder(), corpus, new FakeEmbedder(withSparse),
            NullLogger<KnowledgeRetrievalService>.Instance);

        return (service, corpus);
    }

    // ---- acceptance criterion 1 --------------------------------------------------------------
    // "Given a dependency finding with a CVE, when retrieved, then the exact payload filter
    //  returns the CVE record first."

    [Fact]
    public async Task A_dependency_finding_with_a_cve_is_answered_by_the_exact_filter()
    {
        var (service, corpus) = Build();

        var result = await service.RetrieveAsync(
            FindingFixture.Dependency(), RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.ExactFilter, result.Mode);
        Assert.Equal("nvd-cve-2024-21907", result.Chunks[0].ChunkId);
        Assert.Equal("CVE-2024-21907", result.Chunks[0].CveId);

        // No embedding happened at all — the exact arm is deterministic and free.
        Assert.Empty(corpus.Searches);
    }

    // ---- acceptance criterion 2 --------------------------------------------------------------
    // "Given an infra finding without an ID, when retrieved, then the semantic path is
    //  source-filtered to techniques/guidance, not flooded by CVEs."

    [Fact]
    public async Task An_infra_finding_with_no_identifier_takes_the_source_filtered_semantic_path()
    {
        var (service, corpus) = Build();

        var finding = FindingFixture.Infra();
        finding.CweId = null;
        finding.CveId = null;

        var result = await service.RetrieveAsync(finding, RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.Hybrid, result.Mode);
        Assert.NotEmpty(result.Chunks);

        // Techniques and attack patterns, and no CVE anywhere in the results.
        Assert.All(result.Chunks, c =>
            Assert.Contains(c.Source, new[] { KnowledgeSource.Attack, KnowledgeSource.Capec }));
        Assert.DoesNotContain(result.Chunks, c => c.Source == KnowledgeSource.Nvd);

        var (query, _) = Assert.Single(corpus.Searches);
        Assert.True(query.IsFiltered);
        Assert.Equal(KnowledgeCollection.Offense, query.Collection);
    }

    /// <summary>
    /// The counterfactual: what the same query returns with no filter. This is the measurement
    /// §4 records, and the reason the filter is mandatory rather than recommended.
    /// </summary>
    [Fact]
    public async Task Without_the_filter_the_same_query_would_have_returned_cves()
    {
        var (service, corpus) = Build();

        var finding = FindingFixture.Infra();
        finding.CweId = null;
        finding.CveId = null;
        var filtered = await service.RetrieveAsync(finding, RetrievalIntent.HowToFix);

        // What the same text would have returned with no filter at all — the measurement
        // PIPELINE_A_CONTEXT.md §4 records, and the reason the filter is mandatory.
        var text = Assert.Single(corpus.Searches).Query.Text;
        var unfiltered = corpus.UnfilteredForTestingOnly(text, KnowledgeCollection.Defense);

        Assert.DoesNotContain(filtered.Chunks, c => c.Source == KnowledgeSource.Nvd);
        Assert.Contains(unfiltered, c => c.Source == KnowledgeSource.Nvd);
    }

    // ---- acceptance criterion 3 --------------------------------------------------------------
    // "Given identical index and query embedders, when hybrid runs, then dense+sparse are fused
    //  via RRF."

    [Fact]
    public async Task Hybrid_runs_when_the_embedder_has_a_sparse_half()
    {
        var (service, corpus) = Build(withSparse: true);

        var finding = FindingFixture.Infra();
        finding.CweId = null;

        var result = await service.RetrieveAsync(finding, RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.Hybrid, result.Mode);

        var (_, vectors) = Assert.Single(corpus.Searches);
        Assert.True(vectors.SupportsHybrid);
        Assert.NotNull(vectors.Sparse);
        Assert.Equal(1024, vectors.Dense.Count);
    }

    /// <summary>
    /// The Azure path. <c>text-embedding-3-large</c> has no lexical half, and the reference
    /// implementation degrades to dense-only rather than sending an empty sparse prefetch that
    /// matches nothing.
    /// </summary>
    [Fact]
    public async Task Semantic_degrades_to_dense_only_when_the_embedder_has_no_sparse_half()
    {
        var (service, corpus) = Build(withSparse: false);

        var finding = FindingFixture.Infra();
        finding.CweId = null;

        var result = await service.RetrieveAsync(finding, RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.Semantic, result.Mode);

        var (_, vectors) = Assert.Single(corpus.Searches);
        Assert.False(vectors.SupportsHybrid);
        Assert.Null(vectors.Sparse);
    }

    // ---- the mandatory source condition on the exact arm --------------------------------------

    /// <summary>
    /// The 825-versus-2 measurement, reproduced. Twenty NVD chunks in the fake corpus carry
    /// <c>cwe_id=CWE-502</c>; only two are the weakness itself.
    /// </summary>
    [Fact]
    public async Task A_cwe_lookup_returns_the_weakness_definition_not_the_cves_tagged_with_it()
    {
        var (service, corpus) = Build();

        var finding = FindingFixture.Code();       // CWE-502, no CVE
        var result = await service.RetrieveAsync(finding, RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.ExactFilter, result.Mode);
        Assert.All(result.Chunks, c => Assert.Equal(KnowledgeSource.Cwe, c.Source));
        Assert.Contains(result.Chunks, c => c.ChunkId == "cwe-502");

        var lookup = Assert.Single(corpus.ExactLookups);
        Assert.Equal(KnowledgeSource.Cwe, lookup.Source);
        Assert.Equal(CorpusFields.CweId, lookup.Field);
    }

    // ---- the CWE fallback, and reporting the miss ----------------------------------------------

    /// <summary>
    /// §7: "CVE coverage is partial by design... Report the miss rather than hiding it."
    /// </summary>
    [Fact]
    public async Task A_cve_outside_the_corpus_falls_back_to_the_weakness_class_and_says_so()
    {
        var (service, corpus) = Build();

        var finding = FindingFixture.Code();
        finding.CveId = "CVE-1999-0001";           // well-formed, deliberately not in the slice
        finding.CweId = "CWE-502";

        var result = await service.RetrieveAsync(finding, RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.ExactFilter, result.Mode);
        Assert.Contains(result.Chunks, c => c.ChunkId == "cwe-502");

        Assert.True(result.FellBackToWeaknessClass);
        var miss = Assert.Single(result.Misses);
        Assert.Equal("CVE-1999-0001", miss.Identifier);
        Assert.Contains("not in the corpus", miss.Reason, StringComparison.Ordinal);

        // Both arms were tried, CVE first.
        Assert.Equal(2, corpus.ExactLookups.Count);
        Assert.Equal(KnowledgeSource.Nvd, corpus.ExactLookups[0].Source);
        Assert.Equal(KnowledgeSource.Cwe, corpus.ExactLookups[1].Source);
    }

    [Fact]
    public async Task A_finding_with_neither_identifier_records_that_it_had_no_exact_key()
    {
        var (service, _) = Build();

        var finding = FindingFixture.Infra();
        finding.CweId = null;
        finding.CveId = null;

        var result = await service.RetrieveAsync(finding, RetrievalIntent.HowToFix);

        Assert.Contains(result.Misses, m => m.Reason.Contains("no clean CVE or CWE", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_finding_nothing_matches_is_reported_ungrounded_rather_than_quietly_empty()
    {
        var (service, _) = Build();

        var finding = FindingFixture.Infra();
        finding.CweId = null;
        finding.CveId = null;
        finding.Message = "zzzz qqqq wwww";        // no overlap with anything in the corpus

        var result = await service.RetrieveAsync(finding, RetrievalIntent.HowToFix);

        Assert.Equal(RetrievalMode.None, result.Mode);
        Assert.False(result.IsGrounded);
        Assert.Contains(result.Misses, m => m.Reason.Contains("ungrounded", StringComparison.Ordinal)
                                         || m.Reason.Contains("retrieved no knowledge", StringComparison.Ordinal));
    }

    // ---- intents --------------------------------------------------------------------------------

    [Theory]
    [InlineData(RetrievalIntent.HowToFix, KnowledgeCollection.Defense)]
    [InlineData(RetrievalIntent.HowToDetect, KnowledgeCollection.Defense)]
    [InlineData(RetrievalIntent.WhatTheStandardSays, KnowledgeCollection.Defense)]
    [InlineData(RetrievalIntent.HowAnAttackerWould, KnowledgeCollection.Offense)]
    public async Task Each_intent_reads_the_collection_its_question_belongs_to(
        RetrievalIntent intent, KnowledgeCollection expected)
    {
        var (service, corpus) = Build();

        var finding = FindingFixture.Infra();
        finding.CweId = null;
        finding.CveId = null;

        await service.RetrieveAsync(finding, intent);

        var (query, _) = Assert.Single(corpus.Searches);
        Assert.Equal(expected, query.Collection);
    }

    [Fact]
    public async Task Asking_how_to_fix_returns_remediation_rather_than_cve_descriptions()
    {
        var (service, _) = Build();

        var finding = FindingFixture.Code();
        finding.CweId = null;                      // force the semantic arm
        finding.CveId = null;

        var result = await service.RetrieveAsync(finding, RetrievalIntent.HowToFix);

        Assert.NotEmpty(result.Chunks);
        Assert.DoesNotContain(result.Chunks, c => c.Source == KnowledgeSource.Nvd);
    }

    // ---- batch -----------------------------------------------------------------------------------

    [Fact]
    public async Task RetrieveAll_preserves_input_order_and_grounds_every_fixture_finding()
    {
        var (service, _) = Build();
        var findings = FindingFixture.All();

        var results = await service.RetrieveAllAsync(findings, RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(findings.Select(f => f.Id), results.Select(r => r.FindingId));
        Assert.All(results, r => Assert.True(r.IsGrounded));
    }

    /// <summary>SEC-25 will assert this; SEC-22 has to make it possible.</summary>
    [Fact]
    public async Task All_three_modes_fire_across_the_fixture()
    {
        var (service, _) = Build();

        var withCve = FindingFixture.Dependency();

        var withCweOnly = FindingFixture.Code();

        var withNeither = FindingFixture.Infra();
        withNeither.CweId = null;
        withNeither.CveId = null;

        var hybrid = await service.RetrieveAsync(withNeither, RetrievalIntent.HowAnAttackerWould);
        var exact = await service.RetrieveAsync(withCve, RetrievalIntent.HowAnAttackerWould);
        var alsoExact = await service.RetrieveAsync(withCweOnly, RetrievalIntent.HowAnAttackerWould);

        var (denseOnly, _) = Build(withSparse: false);
        var semantic = await denseOnly.RetrieveAsync(withNeither, RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.ExactFilter, exact.Mode);
        Assert.Equal(RetrievalMode.ExactFilter, alsoExact.Mode);
        Assert.Equal(RetrievalMode.Hybrid, hybrid.Mode);
        Assert.Equal(RetrievalMode.Semantic, semantic.Mode);
    }
}

using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// The guards that make the two mandatory rules unrepresentable rather than merely documented.
/// </summary>
public class RetrievalContractTests
{
    // ---- the exact arm cannot omit its source condition -----------------------------------------

    [Fact]
    public void An_exact_cve_lookup_always_carries_source_nvd()
    {
        var lookup = ExactLookup.ForCve("CVE-2024-21907", KnowledgeCollection.Offense);

        Assert.Equal(CorpusFields.CveId, lookup.Field);
        Assert.Equal("CVE-2024-21907", lookup.Value);
        Assert.Equal(KnowledgeSource.Nvd, lookup.Source);
    }

    [Fact]
    public void An_exact_cwe_lookup_always_carries_source_cwe()
    {
        var lookup = ExactLookup.ForCwe("CWE-502", KnowledgeCollection.Defense);

        Assert.Equal(CorpusFields.CweId, lookup.Field);
        Assert.Equal(KnowledgeSource.Cwe, lookup.Source);
    }

    /// <summary>
    /// There is no constructor to call. This is the compile-time half of the 825-versus-2 guard:
    /// a lookup without a source cannot be written, so it cannot be shipped.
    /// </summary>
    [Fact]
    public void ExactLookup_exposes_no_public_constructor()
    {
        Assert.Empty(typeof(ExactLookup).GetConstructors());
    }

    [Theory]
    [InlineData("cve-2024-21907", "CVE-2024-21907")]
    [InlineData("CVE 2024 21907", "CVE-2024-21907")]
    public void A_sloppy_identifier_is_normalized_into_the_form_the_corpus_indexed(string raw, string expected)
    {
        Assert.Equal(expected, ExactLookup.ForCve(raw, KnowledgeCollection.Offense).Value);
    }

    [Theory]
    [InlineData("not-an-id")]
    [InlineData("CWE-502")]
    public void A_value_that_is_not_a_cve_is_rejected_rather_than_matching_nothing(string raw)
    {
        // Rejected loudly, because "no results" and "malformed id" are indistinguishable
        // downstream and have completely different fixes.
        Assert.Throws<ArgumentException>(() => ExactLookup.ForCve(raw, KnowledgeCollection.Offense));
    }

    // ---- the semantic arm cannot be unfiltered ----------------------------------------------------

    [Fact]
    public void A_semantic_query_with_no_filter_at_all_is_rejected()
    {
        var error = Assert.Throws<ArgumentException>(() =>
            new SemanticQuery("how do I remediate unsafe deserialization", KnowledgeCollection.Defense));

        Assert.Contains("source or content_type filter", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_source_filter_alone_satisfies_the_rule()
    {
        var query = new SemanticQuery(
            "how would an attacker abuse this role", KnowledgeCollection.Offense,
            sources: [KnowledgeSource.Attack, KnowledgeSource.Capec]);

        Assert.True(query.IsFiltered);
    }

    [Fact]
    public void A_content_type_filter_alone_satisfies_the_rule()
    {
        var query = new SemanticQuery(
            "how should I remediate unsafe deserialization", KnowledgeCollection.Defense,
            contentTypes: [KnowledgeContentType.Mitigation]);

        Assert.True(query.IsFiltered);
    }

    [Fact]
    public void A_blank_query_is_rejected()
    {
        Assert.Throws<ArgumentException>(() =>
            new SemanticQuery("   ", KnowledgeCollection.Defense, sources: [KnowledgeSource.Owasp]));
    }

    // ---- the intent table is PIPELINE_A_CONTEXT.md §4 ---------------------------------------------

    [Fact]
    public void How_an_attacker_would_reads_offense_filtered_to_techniques_and_patterns()
    {
        var query = RetrievalIntent.HowAnAttackerWould.ToQuery("privilege escalation via an over-broad role");

        Assert.Equal(KnowledgeCollection.Offense, query.Collection);
        Assert.Equal([KnowledgeSource.Attack, KnowledgeSource.Capec], query.Sources);
        Assert.Empty(query.ContentTypes);
    }

    [Fact]
    public void How_to_fix_reads_defense_filtered_to_mitigations()
    {
        var query = RetrievalIntent.HowToFix.ToQuery("unsafe deserialization");

        Assert.Equal(KnowledgeCollection.Defense, query.Collection);
        Assert.Equal([KnowledgeContentType.Mitigation], query.ContentTypes);
    }

    [Fact]
    public void How_to_detect_reads_defense_filtered_to_detections()
    {
        var query = RetrievalIntent.HowToDetect.ToQuery("valid account abuse");

        Assert.Equal(KnowledgeCollection.Defense, query.Collection);
        Assert.Equal([KnowledgeContentType.Detection], query.ContentTypes);
    }

    [Fact]
    public void What_the_standard_says_reads_defense_filtered_to_owasp()
    {
        var query = RetrievalIntent.WhatTheStandardSays.ToQuery("broken access control");

        Assert.Equal(KnowledgeCollection.Defense, query.Collection);
        Assert.Equal([KnowledgeSource.Owasp], query.Sources);
    }

    [Fact]
    public void Every_intent_produces_a_filtered_query()
    {
        foreach (var intent in Enum.GetValues<RetrievalIntent>())
            Assert.True(intent.ToQuery("anything at all").IsFiltered, $"{intent} produced an unfiltered query");
    }

    // ---- the wire vocabulary crosses repo boundaries ------------------------------------------------

    [Theory]
    [InlineData(KnowledgeSource.Nvd, "NVD")]
    [InlineData(KnowledgeSource.Cwe, "CWE")]
    [InlineData(KnowledgeSource.Attack, "ATTACK")]
    [InlineData(KnowledgeSource.Capec, "CAPEC")]
    [InlineData(KnowledgeSource.Owasp, "OWASP")]
    public void Source_values_match_the_payloads_pipeline_a_wrote(KnowledgeSource source, string expected)
    {
        Assert.Equal(expected, source.Wire());
        Assert.True(CorpusWire.TryReadSource(expected, out var round));
        Assert.Equal(source, round);
    }

    [Theory]
    [InlineData(KnowledgeContentType.Description, "description")]
    [InlineData(KnowledgeContentType.Mitigation, "mitigation")]
    [InlineData(KnowledgeContentType.Detection, "detection")]
    [InlineData(KnowledgeContentType.Prerequisite, "prerequisite")]
    [InlineData(KnowledgeContentType.Guidance, "guidance")]
    public void Content_type_values_match_the_payloads_pipeline_a_wrote(
        KnowledgeContentType contentType, string expected)
    {
        Assert.Equal(expected, contentType.Wire());
    }

    [Theory]
    [InlineData(KnowledgeCollection.Offense, "offense")]
    [InlineData(KnowledgeCollection.Defense, "defense")]
    public void Collection_names_match_the_ones_sec09_created(KnowledgeCollection collection, string expected)
    {
        Assert.Equal(expected, collection.Wire());
    }

    /// <summary>
    /// Filtering on a field Qdrant did not index returns HTTP 400, not a slow scan. Every field
    /// a filter can name has to be in this set.
    /// </summary>
    [Fact]
    public void Every_field_a_filter_keys_on_is_one_qdrant_indexed()
    {
        Assert.Contains(CorpusFields.CveId, CorpusFields.Indexed);
        Assert.Contains(CorpusFields.CweId, CorpusFields.Indexed);
        Assert.Contains(CorpusFields.Source, CorpusFields.Indexed);
        Assert.Contains(CorpusFields.ContentType, CorpusFields.Indexed);

        // Text fields are readable but not filterable — naming them in a filter is the 400.
        Assert.DoesNotContain(CorpusFields.Text, CorpusFields.Indexed);
        Assert.DoesNotContain(CorpusFields.Title, CorpusFields.Indexed);
        Assert.DoesNotContain(CorpusFields.CorpusVersion, CorpusFields.Indexed);
    }

    // ---- sparse vectors ------------------------------------------------------------------------------

    [Fact]
    public void A_sparse_vector_with_mismatched_lengths_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => SparseQueryVector.Create([1u, 2u], [0.5f]));
    }

    [Fact]
    public void Vectors_without_sparse_do_not_claim_hybrid_support()
    {
        Assert.False(new QueryVectors(new float[1024], null).SupportsHybrid);
        Assert.False(new QueryVectors(new float[1024], SparseQueryVector.Create([], [])).SupportsHybrid);
        Assert.True(new QueryVectors(new float[1024], SparseQueryVector.Create([1u], [0.5f])).SupportsHybrid);
    }
}

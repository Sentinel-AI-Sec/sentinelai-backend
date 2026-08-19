using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// SEC-24's policy, on its own. What counts as unfit, what emphatically does not, and the
/// arithmetic that keeps <c>k</c> results coming back.
/// </summary>
/// <remarks>
/// The keep cases carry as much weight as the drop cases here. Over-filtering this corpus is the
/// more expensive mistake — a rule that also dropped <c>Draft</c> and <c>Incomplete</c> would
/// remove 1,641 of the 1,970 status-bearing chunks in offense and leave grounding coverage
/// looking like a corpus gap.
/// </remarks>
public class ChunkQualityTests
{
    private static KnowledgeChunk Chunk(
        string title = "CAPEC-586: Object Injection",
        string? text = null,
        string? status = null,
        KnowledgeSource source = KnowledgeSource.Capec) => new(
            ChunkId: "capec-capec-586",
            Source: source,
            Title: title,
            Text: text ?? "An adversary crafts a serialized object that, when deserialized, "
                        + "constructs a type with side effects.",
            Score: 0.9f,
            Status: status);

    // ---- what is dropped ---------------------------------------------------------------------

    [Theory]
    [InlineData("Deprecated")]
    [InlineData("Obsolete")]
    [InlineData("DEPRECATED")]
    [InlineData("deprecated")]
    [InlineData("oBsOlEtE")]
    public void The_source_status_flag_retires_a_chunk_whatever_case_it_is_written_in(string status)
    {
        // Case-insensitive because two catalogues write it two ways: CWE's XML attribute is
        // 'Deprecated' and CAPEC's x_capec_status is 'Deprecated', but nothing enforces that
        // across releases and a casing change would silently disable the guard.
        Assert.Equal(ChunkDefect.Deprecated, ChunkQuality.Inspect(Chunk(status: status)));
    }

    /// <summary>
    /// The ATT&amp;CK case, and the reason the title is read at all.
    /// </summary>
    /// <remarks>
    /// ATT&amp;CK marks retirement with <c>revoked</c> and <c>x_mitre_deprecated</c>, neither of
    /// which the loader writes into the payload — verified against the live corpus, where no
    /// ATT&amp;CK point carries a <c>status</c> key. MITRE's rename is all that survives ingest.
    /// </remarks>
    [Theory]
    [InlineData("DEPRECATED: Application Deployment Software")]
    [InlineData("Deprecated: Something Withdrawn")]
    [InlineData("  DEPRECATED: leading whitespace still counts")]
    public void A_title_marked_deprecated_retires_a_chunk_even_with_no_status_field(string title)
    {
        var chunk = Chunk(title: title, status: null, source: KnowledgeSource.Attack);

        Assert.Equal(ChunkDefect.Deprecated, ChunkQuality.Inspect(chunk));
    }

    [Fact]
    public void A_chunk_below_the_ingests_minimum_useful_length_is_too_thin_to_cite()
    {
        var chunk = Chunk(text: new string('a', ChunkQuality.MinimumUsefulCharacters - 1));

        Assert.Equal(ChunkDefect.TooThin, ChunkQuality.Inspect(chunk));
    }

    [Fact]
    public void The_length_test_sits_exactly_where_the_ingest_puts_it()
    {
        // Pipeline A's is_over_cleaned drops anything shorter than 40, and the live corpus's
        // shortest chunk is exactly 40 — so 40 must be kept and 39 must not. An off-by-one here
        // either lets stubs through or discards real chunks at the boundary.
        Assert.Equal(ChunkDefect.None, ChunkQuality.Inspect(Chunk(text: new string('a', 40))));
        Assert.Equal(ChunkDefect.TooThin, ChunkQuality.Inspect(Chunk(text: new string('a', 39))));
    }

    [Fact]
    public void Whitespace_padding_does_not_buy_a_stub_its_way_past_the_length_test()
    {
        var chunk = Chunk(text: "Withdrawn." + new string(' ', 100));

        Assert.Equal(ChunkDefect.TooThin, ChunkQuality.Inspect(chunk));
    }

    /// <summary>A retired entry is usually also a stub; it should be reported as retired.</summary>
    [Fact]
    public void Deprecation_is_diagnosed_ahead_of_thinness()
    {
        var chunk = Chunk(text: "Withdrawn.", status: "Deprecated");

        Assert.Equal(ChunkDefect.Deprecated, ChunkQuality.Inspect(chunk));
    }

    // ---- what is kept, and why it matters more -------------------------------------------------

    /// <summary>
    /// The live statuses. Measured counts in <c>offense</c>: Draft 1,155, Incomplete 486,
    /// Stable 325, Usable 4 — and only 26 of the 944 CWE chunks are <c>Stable</c>.
    /// </summary>
    [Theory]
    [InlineData("Draft")]
    [InlineData("Stable")]
    [InlineData("Incomplete")]
    [InlineData("Usable")]
    [InlineData(null)]
    public void Every_status_that_is_not_a_retirement_is_kept(string? status)
    {
        Assert.True(ChunkQuality.IsUsable(Chunk(status: status)));
    }

    /// <summary>
    /// The prefix rule, and the false positive it exists to avoid.
    /// </summary>
    /// <remarks>
    /// CWE-477 "Use of Obsolete Function" and CWE-1104 "Use of Unmaintained Third Party
    /// Components" are live weaknesses whose subject is deprecation. A substring match on
    /// "deprecated" or "obsolete" would delete exactly the guidance a finding about a stale
    /// dependency needs.
    /// </remarks>
    [Theory]
    [InlineData("Use of a Deprecated Cryptographic Algorithm")]
    [InlineData("CWE-477: Use of Obsolete Function")]
    [InlineData("Reliance on Obsolete Encryption")]
    public void A_live_entry_that_merely_talks_about_deprecation_is_kept(string title)
    {
        Assert.True(ChunkQuality.IsUsable(Chunk(title: title)));
    }

    // ---- the over-fetch arithmetic ---------------------------------------------------------------

    [Fact]
    public void The_over_fetch_asks_for_more_than_it_intends_to_return()
    {
        Assert.Equal(20, ChunkQuality.OverFetch(10));
        Assert.True(ChunkQuality.OverFetch(10) > 10);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void An_over_fetch_of_nothing_is_rejected_rather_than_returning_zero(int topK)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ChunkQuality.OverFetch(topK));
    }

    // ---- the acceptance criterion, as arithmetic --------------------------------------------------
    // "Given retrieval results, when filtered, then DEPRECATED entries are removed and k results
    //  remain."

    [Fact]
    public void Deprecated_entries_are_removed_and_k_results_still_remain()
    {
        const int k = 10;

        // What an over-fetch of 2k returns from a corpus whose top eight are retired.
        var retrieved = Enumerable.Range(0, ChunkQuality.OverFetch(k))
            .Select(i => Chunk(status: i < 8 ? "Deprecated" : "Draft") with { ChunkId = $"c{i:00}" })
            .ToList();

        var filtered = ChunkQuality.Apply(retrieved, k);

        Assert.Equal(k, filtered.Chunks.Count);
        Assert.Equal(8, filtered.Dropped);
        Assert.DoesNotContain(filtered.Chunks, c => c.Status == "Deprecated");
    }

    /// <summary>
    /// The counterfactual: without the over-fetch the same corpus returns two chunks, not ten.
    /// </summary>
    [Fact]
    public void Fetching_only_k_would_have_returned_fewer_than_k()
    {
        const int k = 10;

        var retrieved = Enumerable.Range(0, k)
            .Select(i => Chunk(status: i < 8 ? "Deprecated" : "Draft") with { ChunkId = $"c{i:00}" })
            .ToList();

        Assert.Equal(2, ChunkQuality.Apply(retrieved, k).Chunks.Count);
    }

    [Fact]
    public void Ranking_order_is_preserved_because_qdrant_already_decided_it()
    {
        var retrieved = new List<KnowledgeChunk>
        {
            Chunk(status: "Deprecated") with { ChunkId = "rot", Score = 0.99f },
            Chunk() with { ChunkId = "best", Score = 0.90f },
            Chunk() with { ChunkId = "next", Score = 0.80f },
        };

        var filtered = ChunkQuality.Apply(retrieved);

        Assert.Equal(["best", "next"], filtered.Chunks.Select(c => c.ChunkId));
    }

    [Fact]
    public void Chunks_beyond_the_cap_are_not_counted_as_dropped_for_quality()
    {
        // Otherwise SEC-25 reads "10 dropped" on a perfectly healthy corpus and concludes rot.
        var retrieved = Enumerable.Range(0, 20).Select(i => Chunk() with { ChunkId = $"c{i:00}" }).ToList();

        var filtered = ChunkQuality.Apply(retrieved, topK: 10);

        Assert.Equal(10, filtered.Chunks.Count);
        Assert.Equal(0, filtered.Dropped);
        Assert.False(filtered.AnyDropped);
    }

    [Fact]
    public void No_cap_keeps_every_survivor_which_is_what_the_exact_arm_wants()
    {
        var retrieved = Enumerable.Range(0, 16).Select(i => Chunk() with { ChunkId = $"c{i:00}" }).ToList();

        Assert.Equal(16, ChunkQuality.Apply(retrieved).Chunks.Count);
    }

    [Fact]
    public void Losing_everything_is_distinguishable_from_having_retrieved_nothing()
    {
        var allRot = ChunkQuality.Apply([Chunk(status: "Deprecated"), Chunk(status: "Obsolete")]);
        var nothing = ChunkQuality.Apply([]);

        Assert.True(allRot.EverythingDropped);
        Assert.False(nothing.EverythingDropped);
        Assert.Empty(nothing.Chunks);
    }

    [Fact]
    public void A_healthy_result_set_passes_through_untouched()
    {
        var retrieved = new List<KnowledgeChunk> { Chunk(), Chunk(status: "Draft"), Chunk(status: "Stable") };

        var filtered = ChunkQuality.Apply(retrieved, topK: 10);

        Assert.Equal(3, filtered.Chunks.Count);
        Assert.False(filtered.AnyDropped);
    }
}

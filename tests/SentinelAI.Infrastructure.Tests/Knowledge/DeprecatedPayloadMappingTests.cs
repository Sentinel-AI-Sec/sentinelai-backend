using Qdrant.Client.Grpc;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Infrastructure.Knowledge;

namespace SentinelAI.Infrastructure.Tests.Knowledge;

/// <summary>
/// SEC-24 at the wire, without a cluster: the signal the guard judges on actually survives the
/// trip out of a Qdrant payload.
/// </summary>
/// <remarks>
/// <para>
/// The story's policy lives in <c>ChunkQuality</c> and is covered by
/// <c>SentinelAI.Application.Tests</c>; its wiring into the decision tree is covered by
/// <c>LowQualityFilteringTests</c>. Both start from a <see cref="KnowledgeChunk"/> that already
/// has its <c>Status</c> populated. <b>Nothing cluster-free covered the step that populates
/// it</b>, and that step is the one with a cross-repo string in it: <c>status</c> is written by
/// <c>sentinelai_knowledge</c>'s CWE and CAPEC loaders in Python and read here by name.
/// </para>
/// <para>
/// The failure that gap allows is the quiet kind this codebase keeps designing against. Rename
/// the field upstream, or have it arrive as a non-string, and every chunk gets
/// <c>Status = null</c>; <see cref="ChunkQuality.DeadStatuses"/> then matches nothing, half the
/// guard is switched off, and the results still look like results. The one test that would have
/// caught it — <c>LiveCorpusQualityTests.The_adapter_reads_the_status_field_the_guard_depends_on</c>
/// — needs a live corpus and is skipped in CI, so in practice it caught nothing.
/// </para>
/// <para>
/// These build the payload dictionaries Qdrant hands back, with the field names spelled the way
/// the Python loaders spell them rather than via <see cref="CorpusFields"/>. Going through the
/// constant on both sides would make a rename agree with itself and pass.
/// </para>
/// </remarks>
public class DeprecatedPayloadMappingTests
{
    private static Value Str(string value) => new() { StringValue = value };

    /// <summary>
    /// A CAPEC point as <c>loaders/capec.py</c> writes it — live unless told otherwise.
    /// </summary>
    /// <remarks>
    /// Long enough to clear <see cref="ChunkQuality.MinimumUsefulCharacters"/> on purpose: these
    /// tests are about the deprecation signal, and a fixture that tripped the thinness rule as
    /// well would pass for the wrong reason.
    /// </remarks>
    private static Dictionary<string, Value> AttackPattern(
        string id = "capec-586", string title = "Object Injection", string? status = "Draft")
    {
        var payload = new Dictionary<string, Value>
        {
            ["chunk_id"] = Str(id),
            ["source"] = Str("CAPEC"),
            ["title"] = Str(title),
            ["text"] = Str(
                "An adversary supplies a serialised object that the application deserialises "
                + "without constraining the resulting type, turning a data channel into code execution."),
            ["content_type"] = Str("description"),
        };

        if (status is not null) payload["status"] = Str(status);

        return payload;
    }

    // ---- the seam the guard depends on -------------------------------------------------------

    /// <summary>
    /// The reason this file exists: a retired entry's <c>status</c> reaches the guard, and the
    /// guard rejects it.
    /// </summary>
    /// <remarks>
    /// Asserted through <see cref="ChunkQuality.Inspect"/> rather than on the string, because the
    /// contract worth protecting is "the adapter and the policy agree", not "a dictionary lookup
    /// works". A test that only checked <c>chunk.Status == "Deprecated"</c> would still pass if
    /// the two ends disagreed about casing.
    /// </remarks>
    [Theory]
    [InlineData("Deprecated")]
    [InlineData("Obsolete")]
    [InlineData("DEPRECATED")]   // the loaders lower-case before comparing; this side must too
    public void A_retired_status_survives_the_payload_and_the_guard_rejects_it(string status)
    {
        var chunk = QdrantKnowledgeSearch.ToChunk(AttackPattern(status: status), score: 0.91f);

        Assert.Equal(status, chunk.Status);
        Assert.Equal(ChunkDefect.Deprecated, ChunkQuality.Inspect(chunk));
    }

    /// <summary>
    /// The statuses that make up almost the whole corpus survive as usable.
    /// </summary>
    /// <remarks>
    /// The mirror image, and the more dangerous direction. <c>Draft</c> and <c>Incomplete</c> are
    /// 918 of the 944 CWE chunks; a guard that read them as retirement would delete the weakness
    /// catalogue every infra and code finding resolves into, and the symptom would be a corpus
    /// that appears to have nothing in it.
    /// </remarks>
    [Theory]
    [InlineData("Draft")]
    [InlineData("Incomplete")]
    [InlineData("Stable")]
    [InlineData("Usable")]
    public void A_live_status_survives_the_payload_and_the_guard_keeps_it(string status)
    {
        var chunk = QdrantKnowledgeSearch.ToChunk(AttackPattern(status: status), score: 0.91f);

        Assert.Equal(ChunkDefect.None, ChunkQuality.Inspect(chunk));
    }

    /// <summary>
    /// No <c>status</c> key at all — ATT&amp;CK, NVD and OWASP — is "this source has no lifecycle
    /// field", not "retired".
    /// </summary>
    /// <remarks>
    /// Three of the five sources never write the key, so a null <c>Status</c> is the common case
    /// rather than an anomaly. It is also why <see cref="ChunkQuality"/> checks the title as well:
    /// for those sources the title marker is the only deprecation signal there is.
    /// </remarks>
    [Fact]
    public void A_payload_with_no_status_key_is_read_as_live_rather_than_retired()
    {
        var technique = new Dictionary<string, Value>
        {
            ["chunk_id"] = Str("attack-T1059"),
            ["source"] = Str("ATTACK"),
            ["technique_id"] = Str("T1059"),
            ["title"] = Str("Command and Scripting Interpreter"),
            ["text"] = Str(
                "Adversaries may abuse command and script interpreters to execute commands, "
                + "scripts, or binaries on a victim host."),
        };

        var chunk = QdrantKnowledgeSearch.ToChunk(technique, score: 0.88f);

        Assert.Null(chunk.Status);
        Assert.Equal(ChunkDefect.None, ChunkQuality.Inspect(chunk));
    }

    /// <summary>
    /// The ATT&amp;CK half of the story, end to end from a payload: the title marker is what
    /// catches a source that has no <c>status</c> field.
    /// </summary>
    [Fact]
    public void A_deprecated_title_is_caught_on_a_payload_that_carries_no_status()
    {
        var revoked = new Dictionary<string, Value>
        {
            ["chunk_id"] = Str("attack-T1064"),
            ["source"] = Str("ATTACK"),
            ["technique_id"] = Str("T1064"),
            ["title"] = Str("DEPRECATED: Scripting"),
            ["text"] = Str(
                "This technique has been deprecated and split into several sub-techniques of "
                + "Command and Scripting Interpreter."),
        };

        var chunk = QdrantKnowledgeSearch.ToChunk(revoked, score: 0.94f);

        Assert.Null(chunk.Status);
        Assert.Equal(ChunkDefect.Deprecated, ChunkQuality.Inspect(chunk));
    }

    /// <summary>
    /// A <c>status</c> that is not a string reads as absent instead of throwing mid-scan.
    /// </summary>
    /// <remarks>
    /// Qdrant payloads are <c>Value</c> unions, so the type is a run-time fact rather than a
    /// compile-time one. Degrading to null is the right call here — one odd point must not abort a
    /// scan — but it degrades the guard silently, which is exactly the mode this file is pinning
    /// down. Written out so a future change to <c>Text</c> has to make that trade deliberately.
    /// </remarks>
    [Fact]
    public void A_status_that_is_not_a_string_reads_as_absent_rather_than_throwing()
    {
        var payload = AttackPattern(status: null);
        payload["status"] = new Value { IntegerValue = 1 };

        var chunk = QdrantKnowledgeSearch.ToChunk(payload, score: 0.5f);

        Assert.Null(chunk.Status);
    }

    /// <summary>
    /// The rename guard: a lifecycle value stored under any other key does not reach the chunk.
    /// </summary>
    /// <remarks>
    /// This is the failure being defended against, staged. If Pipeline A ever writes
    /// <c>lifecycle_status</c>, or <see cref="CorpusFields.Status"/> is edited to match something
    /// the loaders do not write, the result is this: a retired entry that the guard finds nothing
    /// wrong with. Asserting the miss here means the constant cannot drift alone — the literal in
    /// <see cref="AttackPattern"/> is the loaders' spelling and the two have to keep agreeing.
    /// </remarks>
    [Fact]
    public void A_status_stored_under_a_different_key_never_reaches_the_guard()
    {
        Assert.Equal("status", CorpusFields.Status);

        var payload = AttackPattern(status: null);
        payload["lifecycle_status"] = Str("Deprecated");

        var chunk = QdrantKnowledgeSearch.ToChunk(payload, score: 0.99f);

        Assert.Null(chunk.Status);
        Assert.Equal(ChunkDefect.None, ChunkQuality.Inspect(chunk));
    }

    // ---- the two acceptance criteria, on adapter output --------------------------------------

    /// <summary>
    /// A ranked page as the adapter produces it, worst-first: the retired and thin entries score
    /// above the live ones, which is the whole reason the story exists.
    /// </summary>
    /// <param name="rejects">How many unusable points sit at the top of the page.</param>
    /// <param name="total">How many points the over-fetched query asked for.</param>
    private static List<KnowledgeChunk> RankedPage(int rejects, int total)
    {
        var page = new List<KnowledgeChunk>(total);

        for (var i = 0; i < total; i++)
        {
            // Descending so the list is in the order Qdrant returns it and Apply's
            // order-preserving contract is under test too, not just its arithmetic.
            var score = 1f - (i * 0.01f);

            page.Add(i < rejects

                // Alternating, because the two defects arrive by different routes — a CAPEC
                // status flag and an ATT&CK title marker — and a page of only one kind would
                // leave the other signal unexercised at this level.
                ? QdrantKnowledgeSearch.ToChunk(
                    i % 2 == 0
                        ? AttackPattern($"capec-dead-{i}", "Retired Pattern", "Deprecated")
                        : AttackPattern($"attack-dead-{i}", $"DEPRECATED: Old Technique {i}", status: null),
                    score)

                : QdrantKnowledgeSearch.ToChunk(AttackPattern($"capec-live-{i}", $"Live Pattern {i}"), score));
        }

        return page;
    }

    /// <summary>
    /// Acceptance box 1: DEPRECATED entries are removed. Acceptance box 2: the caller still gets
    /// the number it asked for.
    /// </summary>
    /// <remarks>
    /// Both on one page because they are one property — the count only holds <em>because</em> the
    /// query was over-fetched, and a test that checked the removal on a page of exactly <c>k</c>
    /// would pass while returning three results out of five.
    /// </remarks>
    [Fact]
    public void Deprecated_entries_are_removed_and_the_requested_count_still_comes_back()
    {
        const int topK = SemanticQuery.DefaultTopK;

        // What the semantic arm actually asks Qdrant for, not a number chosen to make this pass.
        var page = RankedPage(rejects: topK, total: ChunkQuality.OverFetch(topK));

        var filtered = ChunkQuality.Apply(page, topK);

        Assert.Equal(topK, filtered.Chunks.Count);
        Assert.Equal(topK, filtered.Dropped);
        Assert.All(filtered.Chunks, c => Assert.Equal(ChunkDefect.None, ChunkQuality.Inspect(c)));

        // Still Qdrant's ranking. SEC-20's one-authority-per-answer rule: the guard removes and
        // does not re-score, so the survivors come back in the order they arrived.
        Assert.Equal(
            filtered.Chunks.Select(c => c.Score).OrderByDescending(s => s),
            filtered.Chunks.Select(c => c.Score));
    }

    /// <summary>
    /// The counter-measurement: the same page fetched at <c>k</c> comes back short.
    /// </summary>
    /// <remarks>
    /// The over-fetch is the design point of this story, so the cost of skipping it is asserted
    /// rather than described. Ten wanted, one returned, and no error anywhere — that is what
    /// "fetch exactly <c>k</c> then filter" buys.
    /// </remarks>
    [Fact]
    public void The_same_page_fetched_at_k_would_have_come_back_short()
    {
        const int topK = SemanticQuery.DefaultTopK;

        var atK = ChunkQuality.Apply(RankedPage(rejects: topK - 1, total: topK), topK);

        Assert.Single(atK.Chunks);
        Assert.Equal(topK - 1, atK.Dropped);
    }
}

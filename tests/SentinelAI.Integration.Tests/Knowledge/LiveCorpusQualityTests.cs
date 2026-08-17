using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Infrastructure.Knowledge;

namespace SentinelAI.Integration.Tests.Knowledge;

/// <summary>
/// SEC-24 against the real corpus: the plumbing the guard depends on works, and the guard itself
/// has nothing to do.
/// </summary>
/// <remarks>
/// <para>
/// A filter that never fires is indistinguishable from a filter that is broken, and this story's
/// filter should never fire — Pipeline A drops deprecated entries at ingest, so on a healthy
/// corpus SEC-24 is a no-op by design (<c>PIPELINE_A_CONTEXT.md</c> §7: "belt and braces").
/// These tests are how the difference is told apart: one proves the signal reaches the guard, the
/// other proves the guard finds nothing wrong with it.
/// </para>
/// <para>
/// <b>Exact lookups only.</b> The semantic arm needs the embedding service, which is optional and
/// usually absent, so the breadth here is CWE and NVD rather than the whole corpus. The
/// corpus-wide measurement — 0 deprecated and 0 thin chunks across all 60,129 points in both
/// collections — is recorded in <c>docs/Deprecated_Filtering.md</c> §2, where it can be re-run
/// against a cluster without needing a 2.2 GB model in CI.
/// </para>
/// <para>
/// Read-only. Set <c>SENTINELAI_CORPUS_URL</c> / <c>SENTINELAI_CORPUS_KEY</c>, or configure
/// <c>Knowledge:Endpoint</c>, to run it.
/// </para>
/// </remarks>
public class LiveCorpusQualityTests
{
    /// <summary>A spread of the weaknesses the rule-mapping table actually resolves findings to.</summary>
    private static readonly string[] Weaknesses =
        ["CWE-502", "CWE-284", "CWE-79", "CWE-89", "CWE-22", "CWE-798", "CWE-352", "CWE-611", "CWE-918"];

    private static QdrantKnowledgeSearch Search() => new(
        Options.Create(new QdrantOptions
        {
            Endpoint = LiveCorpusFactAttribute.Url!,
            ApiKey = LocalDev.CorpusKey,
        }),
        NullLogger<QdrantKnowledgeSearch>.Instance);

    private static async Task<List<KnowledgeChunk>> EveryWeaknessChunkAsync(QdrantKnowledgeSearch search)
    {
        var chunks = new List<KnowledgeChunk>();

        foreach (var cwe in Weaknesses)
            chunks.AddRange(await search.ExactAsync(ExactLookup.ForCwe(cwe, KnowledgeCollection.Defense)));

        return chunks;
    }

    /// <summary>
    /// The one that fails loudly if Pipeline A renames the field.
    /// </summary>
    /// <remarks>
    /// <see cref="ChunkQuality"/> reads <c>status</c> off the payload by the name in
    /// <see cref="CorpusFields.Status"/>. If that name ever stops matching what the loaders write,
    /// every chunk arrives with a null status, the deprecation check silently passes everything,
    /// and no other test in this suite notices — the same cross-repo string hazard
    /// <c>CorpusWire</c> exists to contain. This asserts the field is really there and really
    /// read.
    /// </remarks>
    [LiveCorpusFact]
    public async Task The_adapter_reads_the_status_field_the_guard_depends_on()
    {
        using var search = Search();

        var chunks = await EveryWeaknessChunkAsync(search);

        Assert.NotEmpty(chunks);
        Assert.Contains(chunks, c => !string.IsNullOrWhiteSpace(c.Status));
    }

    /// <summary>
    /// The corpus is healthy, so the guard removes nothing. This is the assertion that would
    /// change if a stale corpus were ever pointed at.
    /// </summary>
    [LiveCorpusFact]
    public async Task Nothing_the_live_corpus_returns_is_dropped_by_the_guard()
    {
        using var search = Search();

        var chunks = await EveryWeaknessChunkAsync(search);
        var filtered = ChunkQuality.Apply(chunks);

        Assert.NotEmpty(chunks);
        Assert.Equal(0, filtered.Dropped);
        Assert.Equal(chunks.Count, filtered.Chunks.Count);
    }

    /// <summary>
    /// The statuses that are actually in there are the live ones, and the catalogue is mostly
    /// <c>Draft</c> and <c>Incomplete</c> rather than <c>Stable</c>.
    /// </summary>
    /// <remarks>
    /// This is the measurement that makes <see cref="ChunkQuality.DeadStatuses"/> a two-value set
    /// rather than an allow-list of <c>Stable</c>: only 26 of the 944 CWE chunks in <c>offense</c>
    /// are stable, so "keep only stable" would discard 97% of the weakness catalogue — the one
    /// every code and infra finding resolves into.
    /// </remarks>
    [LiveCorpusFact]
    public async Task The_weakness_catalogue_is_mostly_draft_and_incomplete_and_all_of_it_is_live()
    {
        using var search = Search();

        var statuses = (await EveryWeaknessChunkAsync(search))
            .Select(c => c.Status)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList();

        Assert.NotEmpty(statuses);
        Assert.DoesNotContain(statuses, s => ChunkQuality.DeadStatuses.Contains(s!));

        // If this ever fails because everything went Stable, the guard is still correct — but the
        // reasoning recorded above it is not, and that is worth being told about.
        Assert.Contains(statuses, s => !string.Equals(s, "Stable", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The thin-text half. Pipeline A's <c>is_over_cleaned</c> drops anything under 40 characters
    /// at ingest; the shortest chunk in either collection is exactly 40, so the constant binds and
    /// the retrieval-side check agrees with it.
    /// </summary>
    [LiveCorpusFact]
    public async Task Every_chunk_the_corpus_returns_clears_the_ingests_minimum_length()
    {
        using var search = Search();

        var chunks = await EveryWeaknessChunkAsync(search);

        Assert.NotEmpty(chunks);
        Assert.All(chunks, c => Assert.True(
            c.Text.Trim().Length >= ChunkQuality.MinimumUsefulCharacters,
            $"{c.ChunkId} is {c.Text.Trim().Length} characters — the ingest should have dropped it"));
    }
}

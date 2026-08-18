using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Handoff;

namespace SentinelAI.Integration.Tests.Knowledge;

/// <summary>
/// SEC-48's second acceptance criterion: an audit records the corpus version it retrieved against.
/// </summary>
/// <remarks>
/// <para>
/// <b>The stamp is observed, not configured.</b> It is read off the chunks retrieval actually
/// returned, so it names the corpus that answered rather than the one settings predicted would.
/// The two can differ — a cluster re-ingested between a job being accepted and being run is the
/// ordinary case — and the citations rest on the retrieved value.
/// </para>
/// <para>
/// These run the real <c>ThinSlicePipeline</c> with a retriever whose chunks carry known corpus
/// versions, so what is asserted is the pipeline's own stamping rather than a mock's memory.
/// </para>
/// </remarks>
public class AuditCorpusStampTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    /// <summary>A retriever whose chunks come from the corpus versions a test names.</summary>
    private sealed class VersionedRetriever(params string?[] versions) : IKnowledgeRetriever
    {
        public Task<RetrievalResult> RetrieveAsync(
            Finding finding, RetrievalIntent intent, CancellationToken ct = default)
        {
            var chunks = versions.Select((v, i) => new KnowledgeChunk(
                ChunkId: $"cwe-502-{i}",
                Source: KnowledgeSource.Cwe,
                Title: "CWE-502",
                Text: "The application deserializes untrusted data without verifying the type.",
                Score: 0f,
                CorpusVersion: v)).ToList();

            return Task.FromResult(new RetrievalResult(
                finding.Id, RetrievalMode.ExactFilter, chunks, []));
        }
    }

    private static async Task<DraftAudit> RunWith(params string?[] versions)
    {
        var result = await HandoffFixture
            .BuildPipeline(retriever: new VersionedRetriever(versions))
            .RunAsync([HandoffFixture.SeededFinding()], Tenant, Job);

        return result.Audit;
    }

    // ---- the acceptance criterion --------------------------------------------------------------

    [Fact]
    public async Task An_audit_records_the_corpus_version_its_knowledge_came_from()
    {
        var audit = await RunWith("2026-08-10-1143");

        Assert.Equal("2026-08-10-1143", audit.CorpusVersion);
        Assert.True(audit.HasCorpusVersion);
    }

    [Fact]
    public async Task One_version_is_recorded_once_however_many_chunks_carry_it()
    {
        var audit = await RunWith("2026-08-10-1143", "2026-08-10-1143", "2026-08-10-1143");

        Assert.Equal("2026-08-10-1143", audit.CorpusVersion);
    }

    // ---- the honest edges ------------------------------------------------------------------------

    /// <summary>
    /// An audit with no retrieved knowledge must not name a corpus it did not use.
    /// </summary>
    /// <remarks>
    /// Taking the stamp from configuration here would let an ungrounded audit claim provenance,
    /// which is precisely the confident-and-unsupported shape the whole system is built to avoid.
    /// </remarks>
    [Fact]
    public async Task An_audit_that_retrieved_nothing_names_no_corpus()
    {
        var audit = await RunWith();

        Assert.Equal(string.Empty, audit.CorpusVersion);
        Assert.False(audit.HasCorpusVersion);
    }

    [Fact]
    public async Task Chunks_from_a_corpus_predating_the_field_do_not_invent_a_version()
    {
        var audit = await RunWith(null, null);

        Assert.False(audit.HasCorpusVersion);
    }

    /// <summary>
    /// Two versions in one scan is an anomaly, so both are recorded rather than one being chosen.
    /// </summary>
    /// <remarks>
    /// It means the collections were re-ingested mid-scan, or two corpora share a cluster.
    /// Picking the newest would produce a plausible single answer and hide that the citations are
    /// not all from the same snapshot — which is exactly the kind of quiet inaccuracy SEC-48 is
    /// meant to make impossible.
    /// </remarks>
    [Fact]
    public async Task Chunks_from_two_corpora_are_both_recorded_rather_than_one_being_picked()
    {
        var audit = await RunWith("2026-08-10-1143", "2026-08-14-2010");

        Assert.Contains("2026-08-10-1143", audit.CorpusVersion, StringComparison.Ordinal);
        Assert.Contains("2026-08-14-2010", audit.CorpusVersion, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_mixed_stamp_is_ordered_so_it_is_stable_across_runs()
    {
        var first = await RunWith("2026-08-14-2010", "2026-08-10-1143");
        var second = await RunWith("2026-08-10-1143", "2026-08-14-2010");

        Assert.Equal(first.CorpusVersion, second.CorpusVersion);
    }
}

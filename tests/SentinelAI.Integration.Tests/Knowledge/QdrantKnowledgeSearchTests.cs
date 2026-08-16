using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Qdrant.Client;
using Qdrant.Client.Grpc;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Infrastructure.Knowledge;

namespace SentinelAI.Integration.Tests.Knowledge;

/// <summary>
/// The SEC-22 Qdrant adapter, against a real index.
/// </summary>
/// <remarks>
/// <para>
/// Skipped unless <c>SENTINELAI_QDRANT</c> names an endpoint — see <see cref="QdrantFactAttribute"/>.
/// </para>
/// <para>
/// It builds a miniature corpus with the composition that makes SEC-22 necessary: one CWE-502
/// weakness definition against twenty NVD chunks merely <em>tagged</em> with CWE-502, and a
/// handful of OWASP guidance chunks against the same NVD bulk. Those are
/// <c>PIPELINE_A_CONTEXT.md</c> §4's two measured failures — the 825-versus-2 exact lookup and
/// the 26,283-versus-172 ranking problem — reproduced at a scale a test can assert on.
/// </para>
/// <para>
/// Vectors are hand-made and deterministic, not embeddings. The adapter's job is to send the
/// right filter and the right prefetch shape; how good a real embedding's ranking is belongs to
/// SEC-25.
/// </para>
/// </remarks>
public sealed class QdrantKnowledgeSearchTests : IAsyncLifetime
{
    private const int Dimensions = 8;

    private QdrantClient _client = null!;
    private QdrantKnowledgeSearch _search = null!;

    /// <summary>
    /// The real collection names, because the adapter derives them from
    /// <see cref="KnowledgeCollection"/> and cannot be pointed at a suffixed copy. Both are
    /// dropped in <see cref="DisposeAsync"/>.
    /// </summary>
    /// <remarks>
    /// <b>Point SENTINELAI_QDRANT at a throwaway instance, never at a real corpus.</b> This
    /// creates and deletes collections called exactly <c>offense</c> and <c>defense</c>. Against
    /// a populated cluster it would destroy the corpus. <c>LiveCorpusSmokeTests</c> is the one
    /// that reads a real corpus, and it only reads.
    /// </remarks>
    private static string Offense => KnowledgeCollection.Offense.Wire();
    private static string Defense => KnowledgeCollection.Defense.Wire();

    public async Task InitializeAsync()
    {
        if (QdrantFactAttribute.Endpoint is not { } endpoint) return;

        _client = new QdrantClient(new Uri(endpoint));

        _search = new QdrantKnowledgeSearch(
            Options.Create(new QdrantOptions { Endpoint = endpoint }),
            NullLogger<QdrantKnowledgeSearch>.Instance);

        // These collections are created and deleted by name. Auto-detection means this could be
        // pointed at a Qdrant somebody actually uses, so refuse rather than destroy: a populated
        // collection here is a real corpus, and losing it costs an ingest.
        await RefuseIfPopulatedAsync(Offense);
        await RefuseIfPopulatedAsync(Defense);

        await SeedAsync(Offense);
        await SeedAsync(Defense);
    }

    public async Task DisposeAsync()
    {
        if (_client is null) return;

        foreach (var name in new[] { Offense, Defense })
        {
            try { await _client.DeleteCollectionAsync(name); }
            catch { /* a collection that never got created is not a failure to clean up */ }
        }

        _search?.Dispose();
        _client.Dispose();
    }

    // ---- the measurement that makes the source condition mandatory --------------------------

    /// <summary>
    /// §4, against a real index: <c>cwe_id=CWE-502</c> alone returns the tagged CVEs; adding
    /// <c>source=CWE</c> returns the weakness definition. Only the second is what a query about
    /// CWE-502 meant to ask.
    /// </summary>
    [QdrantFact]
    public async Task The_source_condition_is_what_separates_the_weakness_from_the_cves_tagged_with_it()
    {
        // What the adapter does, through the type that cannot omit the source.
        var withSource = await _search.ExactAsync(ExactLookup.ForCwe("CWE-502", KnowledgeCollection.Offense));

        // What the same filter returns without it — built by hand here precisely because
        // ExactLookup makes it unrepresentable in production code.
        var withoutSource = await _client.ScrollAsync(
            Offense,
            new Filter
            {
                Must = { new Condition { Field = new FieldCondition { Key = "cwe_id", Match = new Match { Keyword = "CWE-502" } } } },
            },
            limit: 100, payloadSelector: true);

        // Two points: the weakness definition and its mitigations. This is exactly the number
        // PIPELINE_A_CONTEXT.md §4 measured on the live corpus — "cwe_id=CWE-502 + source=CWE
        // -> 2 points, the actual definition".
        Assert.Equal(2, withSource.Count);
        Assert.All(withSource, c => Assert.Equal(KnowledgeSource.Cwe, c.Source));
        Assert.Contains(withSource, c => c.ChunkId == "cwe-502");

        // 22 points carry the tag; 20 of them are CVEs that would have buried the definition.
        // That ratio is the 825-versus-2 failure in miniature.
        Assert.Equal(22, withoutSource.Result.Count);
        Assert.Contains(withoutSource.Result, p => p.Payload["source"].StringValue == "NVD");
    }

    [QdrantFact]
    public async Task An_exact_cve_lookup_returns_that_cve_record()
    {
        var chunks = await _search.ExactAsync(
            ExactLookup.ForCve("CVE-2023-1001", KnowledgeCollection.Offense) with { }, default);

        // The record has to be reachable by its own id, which is the first acceptance criterion.
        Assert.Single(chunks);
        Assert.Equal("CVE-2023-1001", chunks[0].CveId);
        Assert.Equal(0f, chunks[0].Score);   // a payload filter matches; it does not rank
    }

    [QdrantFact]
    public async Task An_exact_lookup_for_something_absent_returns_empty_rather_than_throwing()
    {
        var chunks = await _search.ExactAsync(
            ExactLookup.ForCve("CVE-1999-0001", KnowledgeCollection.Offense) with { }, default);

        // This is the CWE-fallback trigger: empty means "not in the corpus", which the service
        // reports rather than hides.
        Assert.Empty(chunks);
    }

    // ---- source filtering on the semantic path ------------------------------------------------

    [QdrantFact]
    public async Task A_source_filtered_search_excludes_the_nvd_bulk()
    {
        var query = new SemanticQuery(
            "how should I remediate unsafe deserialization", KnowledgeCollection.Defense,
            sources: [KnowledgeSource.Owasp], topK: 5);

        var chunks = await _search.SearchAsync(query, DenseOnly());

        Assert.NotEmpty(chunks);
        Assert.All(chunks, c => Assert.Equal(KnowledgeSource.Owasp, c.Source));
    }

    [QdrantFact]
    public async Task A_content_type_filter_narrows_to_mitigations()
    {
        var query = new SemanticQuery(
            "how should I remediate unsafe deserialization", KnowledgeCollection.Defense,
            contentTypes: [KnowledgeContentType.Mitigation], topK: 5);

        var chunks = await _search.SearchAsync(query, DenseOnly());

        Assert.NotEmpty(chunks);
        Assert.DoesNotContain(chunks, c => c.Source == KnowledgeSource.Nvd);
    }

    // ---- hybrid --------------------------------------------------------------------------------

    /// <summary>
    /// Acceptance criterion 3: when sparse exists, both vectors are prefetched under the same
    /// filter and fused server-side by RRF.
    /// </summary>
    [QdrantFact]
    public async Task Hybrid_fuses_dense_and_sparse_and_still_honours_the_filter()
    {
        var query = new SemanticQuery(
            "unsafe deserialization of untrusted data", KnowledgeCollection.Defense,
            sources: [KnowledgeSource.Owasp], topK: 5);

        var hybrid = await _search.SearchAsync(query, DenseAndSparse());

        Assert.NotEmpty(hybrid);

        // The filter is on each prefetch, not on the outer fusion query. If it were on the
        // outer one, fusion would rank the NVD bulk first and then discard it, and this would
        // come back short or empty.
        Assert.All(hybrid, c => Assert.Equal(KnowledgeSource.Owasp, c.Source));
    }

    [QdrantFact]
    public async Task Hybrid_and_dense_both_answer_so_the_degradation_path_is_real()
    {
        var query = new SemanticQuery(
            "deserialization", KnowledgeCollection.Offense,
            sources: [KnowledgeSource.Capec, KnowledgeSource.Attack], topK: 5);

        var hybrid = await _search.SearchAsync(query, DenseAndSparse());
        var dense = await _search.SearchAsync(query, DenseOnly());

        Assert.NotEmpty(hybrid);
        Assert.NotEmpty(dense);
    }

    // ---- startup compatibility -------------------------------------------------------------------

    [QdrantFact]
    public async Task A_dimension_mismatch_refuses_to_start_rather_than_failing_per_query()
    {
        // The seeded collections are 8-dimensional; the default embedder claims 1024.
        var mismatched = new QdrantKnowledgeSearch(
            Options.Create(new QdrantOptions { Endpoint = QdrantFactAttribute.Endpoint! }),
            NullLogger<QdrantKnowledgeSearch>.Instance);

        // The seeded collections are 8-dimensional; NotConfiguredQueryEmbedder reports 1024.
        // That mismatch is the whole point of the startup check.
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => mismatched.VerifyCompatibleAsync(new NotConfiguredQueryEmbedder()));

        Assert.Contains("8-dimensional", error.Message, StringComparison.Ordinal);
        Assert.Contains("1024", error.Message, StringComparison.Ordinal);
        mismatched.Dispose();
    }

    // ---- seeding ------------------------------------------------------------------------------------

    private static QueryVectors DenseOnly() => new(Vector(1f), null);

    private static QueryVectors DenseAndSparse() =>
        new(Vector(1f), SparseQueryVector.Create([0u, 1u, 2u], [0.9f, 0.4f, 0.2f]));

    private static float[] Vector(float seed)
    {
        var v = new float[Dimensions];
        for (var i = 0; i < v.Length; i++) v[i] = seed / (i + 1);
        return v;
    }

    /// <summary>
    /// Stops the run before it deletes anything, if the target already holds a corpus.
    /// </summary>
    /// <remarks>
    /// The seeded fixture is 25 points. Anything substantially larger is somebody's real corpus,
    /// and this test would drop it. Cheap to check, and the alternative is unrecoverable.
    /// </remarks>
    private async Task RefuseIfPopulatedAsync(string collection)
    {
        if (!await _client.CollectionExistsAsync(collection)) return;

        var count = await _client.CountAsync(collection);
        if (count <= 64) return;

        throw new InvalidOperationException(
            $"'{collection}' at {QdrantFactAttribute.Endpoint} already holds {count} points. These "
            + "tests create and delete that collection, so this looks like a real corpus and the "
            + "run has been stopped. Point them at a throwaway instance instead.");
    }

    private async Task SeedAsync(string collection)
    {
        // A NAMED "dense" vector, not an unnamed one. store.py creates
        // vectors_config={"dense": VectorParams(...)}, and the adapter queries `using: "dense"`.
        // A bare VectorParams here makes the default unnamed vector, and every upsert fails with
        // "Not existing vector name error: dense" - which is the same shape of mismatch this
        // whole story exists to prevent, arriving in the test's own fixture.
        await _client.CreateCollectionAsync(
            collection,
            new VectorParamsMap
            {
                Map = { ["dense"] = new VectorParams { Size = Dimensions, Distance = Distance.Cosine } },
            },
            sparseVectorsConfig: new SparseVectorConfig { Map = { ["sparse"] = new SparseVectorParams() } });

        foreach (var field in new[] { "chunk_id", "cve_id", "cwe_id", "source", "content_type" })
            await _client.CreatePayloadIndexAsync(collection, field, PayloadSchemaType.Keyword);

        var points = new List<PointStruct>();
        var id = 1ul;

        points.Add(Point(id++, "cwe-502", "CWE", "description",
            "Deserialization of untrusted data lets an attacker control the constructed type.",
            cweId: "CWE-502"));

        points.Add(Point(id++, "cwe-502-mitigations", "CWE", "mitigation",
            "Do not deserialize untrusted input; remediate by binding to an allow-list of types.",
            cweId: "CWE-502"));

        // The twenty tagged CVEs — the 825, in miniature.
        for (var i = 1; i <= 20; i++)
        {
            points.Add(Point(id++, $"nvd-cve-2023-{1000 + i}", "NVD", "description",
                "Unsafe deserialization allows remote code execution; remediate by upgrading.",
                cveId: $"CVE-2023-{1000 + i}", cweId: "CWE-502"));
        }

        points.Add(Point(id++, "owasp-2021-a08-s00", "OWASP", "guidance",
            "Do not deserialize untrusted input. Remediate with integrity checks on serialized objects."));

        points.Add(Point(id++, "capec-capec-586", "CAPEC", "description",
            "An adversary crafts a serialized object that constructs a type with side effects."));

        points.Add(Point(id, "attack-t1078", "ATTACK", "description",
            "Adversaries abuse valid accounts; deserialization can be the initial foothold."));

        await _client.UpsertAsync(collection, points, wait: true);
    }

    private static PointStruct Point(
        ulong id, string chunkId, string source, string contentType, string text,
        string? cveId = null, string? cweId = null)
    {
        var point = new PointStruct
        {
            Id = id,
            Vectors = new Dictionary<string, Vector>
            {
                ["dense"] = Vector(1f),
                ["sparse"] = (new[] { 0.8f, 0.3f, 0.1f }, new[] { 0u, 1u, 2u }),
            },
        };

        point.Payload.Add("chunk_id", chunkId);
        point.Payload.Add("source", source);
        point.Payload.Add("content_type", contentType);
        point.Payload.Add("title", chunkId);
        point.Payload.Add("text", text);
        point.Payload.Add("corpus_version", "test-corpus");

        if (cveId is not null) point.Payload.Add("cve_id", cveId);
        if (cweId is not null) point.Payload.Add("cwe_id", cweId);

        return point;
    }
}

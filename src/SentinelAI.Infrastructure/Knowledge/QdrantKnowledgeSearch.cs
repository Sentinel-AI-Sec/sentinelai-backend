using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Qdrant.Client;
using Qdrant.Client.Grpc;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Infrastructure.Knowledge;

/// <summary>
/// The Qdrant adapter behind <see cref="IKnowledgeSearch"/> (SEC-22 / SEC-09).
/// </summary>
/// <remarks>
/// <para>
/// A translation layer and nothing else. Every retrieval <em>decision</em> — which mode, which
/// filter, what to do when a CVE misses — belongs to <c>KnowledgeRetrievalService</c>, which is
/// pure and unit-tested. This class turns those decisions into gRPC calls and turns payloads back
/// into <see cref="KnowledgeChunk"/>s.
/// </para>
/// <para>
/// The three call shapes mirror <c>sentinelai_knowledge/validate.py</c>, which is the
/// implementation already validated against the live corpus (58 integration checks):
/// <c>scroll</c> with a payload filter for exact, <c>query_points</c> with
/// <c>using="dense"</c> for semantic, and prefetch-both-then-<c>FusionQuery(RRF)</c> for hybrid.
/// Deviating from a shape that has been measured, in favour of one that looks equivalent, is how
/// the query side stops matching the index side.
/// </para>
/// </remarks>
public sealed class QdrantKnowledgeSearch : IKnowledgeSearch, IDisposable
{
    /// <summary>The named vectors SEC-09 created on both collections.</summary>
    private const string DenseVectorName = "dense";
    private const string SparseVectorName = "sparse";

    /// <summary>
    /// How many chunks an exact filter may return.
    /// </summary>
    /// <remarks>
    /// A correct lookup returns a handful — the CWE-502 definition is two chunks. The cap is a
    /// backstop against a filter that has lost its source condition and matched 825 points; it
    /// bounds the damage rather than preventing it, which <see cref="ExactLookup"/> already does.
    /// </remarks>
    private const uint ExactLimit = 16;

    private readonly QdrantClient _client;
    private readonly QdrantOptions _options;
    private readonly ILogger<QdrantKnowledgeSearch> _logger;

    public QdrantKnowledgeSearch(IOptions<QdrantOptions> options, ILogger<QdrantKnowledgeSearch> logger)
    {
        _options = options.Value;
        _logger = logger;

        var uri = new Uri(_options.Endpoint);
        _client = string.IsNullOrWhiteSpace(_options.ApiKey)
            ? new QdrantClient(uri)
            : new QdrantClient(uri, apiKey: _options.ApiKey);
    }

    /// <summary>Mode 1: a payload filter over the index. No vector is involved.</summary>
    public async Task<IReadOnlyList<KnowledgeChunk>> ExactAsync(
        ExactLookup lookup, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(lookup);

        var filter = new Filter
        {
            Must =
            {
                Match(lookup.Field, lookup.Value),

                // Not optional, and not defensive. Without it, cwe_id=CWE-502 returns 825 points
                // whose top 3 are NVD CVEs merely tagged with that weakness.
                Match(CorpusFields.Source, lookup.Source.Wire()),
            },
        };

        var points = await _client.ScrollAsync(
            lookup.Collection.Wire(), filter, limit: ExactLimit, payloadSelector: true,
            cancellationToken: ct);

        var chunks = points.Result.Select(p => ToChunk(p.Payload, score: 0f)).ToList();

        _logger.LogDebug("Exact lookup {Lookup} returned {Count} chunk(s)", lookup, chunks.Count);

        return chunks;
    }

    /// <summary>Modes 2 and 3: filter, then rank — hybrid when the embedder has a sparse half.</summary>
    public async Task<IReadOnlyList<KnowledgeChunk>> SearchAsync(
        SemanticQuery query, QueryVectors vectors, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(vectors);

        var filter = BuildFilter(query);
        var dense = vectors.Dense.ToArray();
        var limit = (ulong)query.TopK;

        var points = vectors.SupportsHybrid
            ? await HybridAsync(query, vectors, dense, filter, limit, ct)
            : await DenseAsync(query, dense, filter, limit, ct);

        return [.. points.Select(p => ToChunk(p.Payload, p.Score))];
    }

    /// <summary>
    /// Dense + sparse, each prefetched under the same filter, fused by Reciprocal Rank Fusion.
    /// </summary>
    /// <remarks>
    /// <b>The filter goes on each prefetch, not on the outer query.</b> Fusion combines whatever
    /// the prefetches returned; filtering afterwards would rank the CVE bulk first and then
    /// discard it, returning fewer than <c>k</c> results — or none — while looking like it
    /// worked. Both branches must be narrowed before they are ranked.
    /// </remarks>
    private async Task<IReadOnlyList<ScoredPoint>> HybridAsync(
        SemanticQuery query, QueryVectors vectors, float[] dense, Filter filter, ulong limit, CancellationToken ct)
    {
        var sparse = vectors.Sparse!;
        var prefetchLimit = (ulong)(query.TopK * Math.Max(1, _options.PrefetchMultiplier));

        var prefetch = new List<PrefetchQuery>
        {
            new() { Query = dense, Using = DenseVectorName, Filter = filter, Limit = prefetchLimit },
            new()
            {
                // The tuple is (values, indices) — that order, not the other one. Swapping them
                // is accepted by the compiler and matches nothing at run time.
                Query = (sparse.Values.ToArray(), sparse.Indices.ToArray()),
                Using = SparseVectorName,
                Filter = filter,
                Limit = prefetchLimit,
            },
        };

        var response = await _client.QueryAsync(
            query.Collection.Wire(),
            query: Fusion.Rrf,
            prefetch: prefetch,
            limit: limit,
            payloadSelector: true,
            cancellationToken: ct);

        _logger.LogDebug("Hybrid search {Query} fused {Count} chunk(s) via RRF", query, response.Count);

        return response;
    }

    /// <summary>Dense only — the path an embedder with no lexical half degrades to.</summary>
    private async Task<IReadOnlyList<ScoredPoint>> DenseAsync(
        SemanticQuery query, float[] dense, Filter filter, ulong limit, CancellationToken ct)
    {
        var response = await _client.QueryAsync(
            query.Collection.Wire(),
            query: dense,
            usingVector: DenseVectorName,
            filter: filter,
            limit: limit,
            payloadSelector: true,
            cancellationToken: ct);

        _logger.LogDebug("Dense search {Query} returned {Count} chunk(s)", query, response.Count);

        return response;
    }

    /// <summary>
    /// The mandatory narrowing, as a Qdrant filter.
    /// </summary>
    /// <remarks>
    /// Source and content-type conditions are ANDed with each other but ORed within themselves —
    /// "ATT&amp;CK or CAPEC", not "both", which no chunk could satisfy. That is what
    /// <c>Match.Keywords</c> means, and it is why the multi-value case does not become several
    /// <c>Must</c> entries.
    /// </remarks>
    private static Filter BuildFilter(SemanticQuery query)
    {
        var filter = new Filter();

        if (query.Sources.Count > 0)
            filter.Must.Add(MatchAny(CorpusFields.Source, query.Sources.Select(s => s.Wire())));

        if (query.ContentTypes.Count > 0)
            filter.Must.Add(MatchAny(CorpusFields.ContentType, query.ContentTypes.Select(c => c.Wire())));

        return filter;
    }

    private static Condition Match(string field, string value) => new()
    {
        Field = new FieldCondition { Key = field, Match = new Match { Keyword = value } },
    };

    private static Condition MatchAny(string field, IEnumerable<string> values)
    {
        var keywords = new RepeatedStrings();
        keywords.Strings.AddRange(values);

        return new Condition
        {
            Field = new FieldCondition { Key = field, Match = new Match { Keywords = keywords } },
        };
    }

    /// <summary>
    /// Reads a Qdrant payload into the Application's chunk shape.
    /// </summary>
    /// <remarks>
    /// Field names come from <see cref="CorpusFields"/> rather than string literals: they are
    /// written by a different repository in a different language, and a typo here produces a
    /// chunk with a null citation key rather than an error.
    /// </remarks>
    private static KnowledgeChunk ToChunk(IReadOnlyDictionary<string, Value> payload, float score)
    {
        CorpusWire.TryReadSource(Text(payload, CorpusFields.Source), out var source);

        return new KnowledgeChunk(
            ChunkId: Text(payload, CorpusFields.ChunkId) ?? string.Empty,
            Source: source,
            Title: Text(payload, CorpusFields.Title) ?? string.Empty,
            Text: Text(payload, CorpusFields.Text) ?? string.Empty,
            Score: score,
            CorpusVersion: Text(payload, CorpusFields.CorpusVersion),
            CveId: Text(payload, CorpusFields.CveId),
            CweId: Text(payload, CorpusFields.CweId),
            CapecIds: List(payload, "capec_ids"),
            TechniqueId: Text(payload, CorpusFields.TechniqueId));
    }

    private static string? Text(IReadOnlyDictionary<string, Value> payload, string key) =>
        payload.TryGetValue(key, out var value) && value.KindCase == Value.KindOneofCase.StringValue
            ? value.StringValue
            : null;

    private static IReadOnlyList<string>? List(IReadOnlyDictionary<string, Value> payload, string key)
    {
        if (!payload.TryGetValue(key, out var value) || value.KindCase != Value.KindOneofCase.ListValue)
            return null;

        return [.. value.ListValue.Values
            .Where(v => v.KindCase == Value.KindOneofCase.StringValue)
            .Select(v => v.StringValue)];
    }

    /// <summary>
    /// Checks the collections exist and their dense width matches the embedder's.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The cheap half of the same-model invariant, run at startup rather than per finding. It
    /// cannot prove the same model was used — two different 1024-dimensional models pass — but a
    /// width mismatch is free to detect and is otherwise found one query at a time, inside a
    /// scan, as a gRPC error per finding.
    /// </para>
    /// <para>
    /// SEC-48 owns the real assertion: compare the embedder's pinned revision against the corpus
    /// manifest's. That needs Pipeline A to publish the manifest, which it does not yet.
    /// </para>
    /// </remarks>
    public async Task VerifyCompatibleAsync(IQueryEmbedder embedder, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(embedder);

        foreach (var collection in Enum.GetValues<KnowledgeCollection>())
        {
            var name = collection.Wire();

            if (!await _client.CollectionExistsAsync(name, ct))
            {
                throw new InvalidOperationException(
                    $"The '{name}' collection does not exist at {_options.Endpoint}. Pipeline A "
                    + "(SEC-06 to SEC-09) has to have run against this cluster before Pipeline B "
                    + "can retrieve from it.");
            }

            var info = await _client.GetCollectionInfoAsync(name, ct);
            var vectors = info.Config?.Params?.VectorsConfig?.ParamsMap?.Map;

            if (vectors is null || !vectors.TryGetValue(DenseVectorName, out var dense)) continue;

            if (dense.Size != (ulong)embedder.DenseDimensions)
            {
                throw new InvalidOperationException(
                    $"Collection '{name}' stores {dense.Size}-dimensional dense vectors but the "
                    + $"query embedder ({embedder.Model} @ {embedder.Revision}) produces "
                    + $"{embedder.DenseDimensions}. Index-time and query-time vectors must come "
                    + "from the same model, or similarity scores are meaningless and nothing errors.");
            }
        }

        _logger.LogInformation(
            "Knowledge corpus at {Endpoint} accepts {Model} @ {Revision} ({Dimensions}-dim dense)",
            _options.Endpoint, embedder.Model, embedder.Revision, embedder.DenseDimensions);
    }

    public void Dispose() => _client.Dispose();
}

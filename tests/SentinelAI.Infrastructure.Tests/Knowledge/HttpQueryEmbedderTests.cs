using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelAI.Infrastructure.Knowledge;

namespace SentinelAI.Infrastructure.Tests.Knowledge;

/// <summary>
/// The adapter over the BGE-M3 service, exercised against a stub handler.
/// </summary>
/// <remarks>
/// No network and no model: what can go wrong here is not the embedding, it is the boundary —
/// whether sparse survives the JSON, whether a wrong-width vector is refused, whether a sleeping
/// Space produces a message that names the cause, and whether anything ever falls back instead of
/// failing. All of that is testable in milliseconds, and all of it fails silently if it is wrong.
/// </remarks>
public class HttpQueryEmbedderTests
{
    private const string Dense1024 = "[[" + "0.1," + "0.1," + "0.1]]";

    /// <summary>A handler that answers from a queue of canned responses and records the requests.</summary>
    private sealed class StubHandler(params HttpResponseMessage[] responses) : HttpMessageHandler
    {
        private readonly Queue<HttpResponseMessage> _responses = new(responses);

        public List<(string Path, string? Body)> Requests { get; } = [];
        public Func<CancellationToken, Task>? BeforeRespond { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add((
                request.RequestUri!.AbsolutePath,
                request.Content is null ? null : await request.Content.ReadAsStringAsync(ct)));

            if (BeforeRespond is not null) await BeforeRespond(ct);

            return _responses.Count > 0
                ? _responses.Dequeue()
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = Json("{}") };
        }
    }

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    private static HttpResponseMessage Ok(string body) =>
        new(HttpStatusCode.OK) { Content = Json(body) };

    private static EmbedderServiceOptions Options(Action<EmbedderServiceOptions>? tweak = null)
    {
        var options = new EmbedderServiceOptions
        {
            BaseUrl = "http://localhost:7860",
            DenseDimensions = 3,
            TimeoutSeconds = 5,
            ColdStartTimeoutSeconds = 10,
        };

        tweak?.Invoke(options);
        return options;
    }

    private static HttpQueryEmbedder Build(StubHandler handler, Action<EmbedderServiceOptions>? tweak = null) =>
        new(new HttpClient(handler),
            Microsoft.Extensions.Options.Options.Create(Options(tweak)),
            NullLogger<HttpQueryEmbedder>.Instance);

    /// <summary>The shape service/app.py returns — dense plus BGE-M3's lexical half.</summary>
    private const string DenseAndSparse = """
        {
          "model": "bge:BAAI/bge-m3",
          "dim": 3,
          "dense": [[0.1, 0.2, 0.3]],
          "sparse": [{"indices": [6, 2723], "values": [0.5, 0.25]}]
        }
        """;

    // ---- the happy path ----------------------------------------------------------------------

    [Fact]
    public async Task Embedding_returns_both_halves_so_hybrid_search_can_run()
    {
        var handler = new StubHandler(Ok(DenseAndSparse));

        var vectors = await Build(handler).EmbedAsync("unsafe deserialization");

        Assert.Equal([0.1f, 0.2f, 0.3f], vectors.Dense);
        Assert.NotNull(vectors.Sparse);
        Assert.Equal([6u, 2723u], vectors.Sparse.Indices);
        Assert.Equal([0.5f, 0.25f], vectors.Sparse.Values);

        // Sparse is the entire reason for running our own service rather than a commercial
        // embedding API — without it mode 3 could never fire.
        Assert.True(vectors.SupportsHybrid);
    }

    [Fact]
    public async Task It_asks_the_service_for_sparse_and_sends_the_query_verbatim()
    {
        var handler = new StubHandler(Ok(DenseAndSparse));

        await Build(handler).EmbedAsync("s3:* on the crown jewel");

        var (path, body) = Assert.Single(handler.Requests);
        Assert.Equal("/embed", path);
        Assert.Contains("\"return_sparse\":true", body, StringComparison.Ordinal);
        Assert.Contains("s3:* on the crown jewel", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task It_reports_the_model_the_corpus_was_indexed_with()
    {
        var embedder = Build(new StubHandler());

        Assert.Equal("BAAI/bge-m3", embedder.Model);
        Assert.Equal("5617a9f61b028005a4858fdac845db406aefb181", embedder.Revision);

        await Task.CompletedTask;
    }

    // ---- sparse absence ----------------------------------------------------------------------

    /// <summary>
    /// Null and empty both mean "no lexical half", and both must produce a null sparse vector —
    /// an empty sparse prefetch matches nothing, so a hybrid search would silently find only the
    /// dense half while reporting that it fused two.
    /// </summary>
    [Theory]
    [InlineData("""{"model":"m","dim":3,"dense":[[0.1,0.2,0.3]],"sparse":[null]}""")]
    [InlineData("""{"model":"m","dim":3,"dense":[[0.1,0.2,0.3]],"sparse":[{"indices":[],"values":[]}]}""")]
    [InlineData("""{"model":"m","dim":3,"dense":[[0.1,0.2,0.3]]}""")]
    public async Task A_service_without_a_lexical_half_yields_no_sparse_vector(string body)
    {
        var vectors = await Build(new StubHandler(Ok(body))).EmbedAsync("anything");

        Assert.Null(vectors.Sparse);
        Assert.False(vectors.SupportsHybrid);
        Assert.Equal(3, vectors.Dense.Count);
    }

    // ---- the failure that would poison everything ---------------------------------------------

    [Fact]
    public async Task A_wrong_width_vector_is_refused_rather_than_queried_with()
    {
        var body = """{"model":"m","dim":5,"dense":[[0.1,0.2,0.3,0.4,0.5]],"sparse":[null]}""";

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build(new StubHandler(Ok(body))).EmbedAsync("anything"));

        Assert.Contains("5-dimensional", error.Message, StringComparison.Ordinal);
        Assert.Contains("indexed at 3", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_empty_response_is_an_error_not_an_empty_vector()
    {
        var body = """{"model":"m","dim":3,"dense":[],"sparse":[]}""";

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build(new StubHandler(Ok(body))).EmbedAsync("anything"));
    }

    // ---- failures name the service --------------------------------------------------------------

    [Fact]
    public async Task A_service_error_names_the_service_and_carries_its_detail()
    {
        var failure = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
        {
            Content = Json("""{"detail":"embedder failed to load: FlagEmbedding is not installed"}"""),
        };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build(new StubHandler(failure)).EmbedAsync("anything"));

        Assert.Contains("localhost:7860", error.Message, StringComparison.Ordinal);
        Assert.Contains("503", error.Message, StringComparison.Ordinal);
        Assert.Contains("FlagEmbedding", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unreachable_service_is_reported_as_unreachable_not_as_an_empty_result()
    {
        var handler = new StubHandler { BeforeRespond = _ => throw new HttpRequestException("connection refused") };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build(handler).EmbedAsync("anything"));

        Assert.Contains("Could not reach the embedding service", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A sleeping free Space is the expected cause of a timeout, so the message says so and names
    /// the setting that fixes it.
    /// </summary>
    [Fact]
    public async Task A_timeout_explains_the_cold_start_and_names_the_setting()
    {
        var handler = new StubHandler { BeforeRespond = async ct => await Task.Delay(Timeout.Infinite, ct) };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build(handler, o => o.ColdStartTimeoutSeconds = 1).EmbedAsync("anything"));

        Assert.Contains("did not answer", error.Message, StringComparison.Ordinal);
        Assert.Contains("ColdStartTimeoutSeconds", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_caller_cancellation_is_not_disguised_as_a_service_timeout()
    {
        var handler = new StubHandler { BeforeRespond = async ct => await Task.Delay(Timeout.Infinite, ct) };
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Build(handler).EmbedAsync("anything", cancelled.Token));
    }

    // ---- warm up ---------------------------------------------------------------------------------

    [Fact]
    public async Task Warming_up_succeeds_and_reports_true()
    {
        var handler = new StubHandler(Ok("""{"status":"ready","seconds":42.5}"""));

        Assert.True(await Build(handler).WarmUpAsync());
        Assert.Equal("/warmup", Assert.Single(handler.Requests).Path);
    }

    /// <summary>
    /// A sleeping service at boot is normal. Throwing here would take down the exact-filter arm
    /// too, which needs no embedder at all.
    /// </summary>
    [Fact]
    public async Task A_failed_warm_up_returns_false_rather_than_taking_the_backend_down()
    {
        var handler = new StubHandler(new HttpResponseMessage(HttpStatusCode.BadGateway));

        Assert.False(await Build(handler).WarmUpAsync());
    }

    // ---- parity ------------------------------------------------------------------------------------

    private const string Parity = """
        {
          "model": "BAAI/bge-m3",
          "dim": 3,
          "sparse": true,
          "norms": [1.0, 0.999999, 1.000001],
          "checksum": [0.5, 0.25, 0.125]
        }
        """;

    [Fact]
    public async Task Parity_passes_when_the_norms_match_the_corpus_baseline()
    {
        var handler = new StubHandler(Ok(Parity));

        await Build(handler, o => o.ExpectedNorms = [1.0, 0.999999, 1.000001]).VerifyParityAsync();

        Assert.Equal("/parity", Assert.Single(handler.Requests).Path);
    }

    /// <summary>
    /// GPU-at-index versus CPU-at-query does not produce bit-identical floats. It produces very
    /// close ones, which the tolerance absorbs.
    /// </summary>
    [Fact]
    public async Task Parity_tolerates_the_drift_between_a_gpu_index_and_a_cpu_query()
    {
        var handler = new StubHandler(Ok(Parity));

        await Build(handler, o => o.ExpectedNorms = [1.00005, 0.99995, 1.00005]).VerifyParityAsync();
    }

    [Fact]
    public async Task Parity_fails_when_a_norm_drifts_further_than_rounding_could_explain()
    {
        var handler = new StubHandler(Ok(Parity));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build(handler, o => o.ExpectedNorms = [1.0, 0.87, 1.000001]).VerifyParityAsync());

        Assert.Contains("drifted", error.Message, StringComparison.Ordinal);
        Assert.Contains("a different model", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Parity_fails_on_a_dimension_mismatch()
    {
        var body = """{"model":"other","dim":768,"sparse":false,"norms":[],"checksum":[]}""";

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build(new StubHandler(Ok(body))).VerifyParityAsync());

        Assert.Contains("768-dimensional", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_baseline_of_the_wrong_length_is_rejected_rather_than_compared_partly()
    {
        var handler = new StubHandler(Ok(Parity));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build(handler, o => o.ExpectedNorms = [1.0]).VerifyParityAsync());

        Assert.Contains("different version", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Without a baseline only the width is checked, and a different model of the same width
    /// would pass — so this must not report a clean bill of health.
    /// </summary>
    [Fact]
    public async Task Parity_without_a_baseline_still_checks_the_width()
    {
        var handler = new StubHandler(Ok(Parity));

        await Build(handler).VerifyParityAsync();

        Assert.Equal("/parity", Assert.Single(handler.Requests).Path);
    }

    // ---- configuration ------------------------------------------------------------------------------

    [Fact]
    public void Registering_it_without_a_url_is_refused_at_construction()
    {
        var error = Assert.Throws<InvalidOperationException>(() => new HttpQueryEmbedder(
            new HttpClient(new StubHandler()),
            Microsoft.Extensions.Options.Options.Create(new EmbedderServiceOptions()),
            NullLogger<HttpQueryEmbedder>.Instance));

        Assert.Contains("NotConfiguredQueryEmbedder", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_configured_api_key_is_sent_as_a_bearer_token()
    {
        var handler = new StubHandler(Ok(DenseAndSparse));
        var http = new HttpClient(handler);

        var embedder = new HttpQueryEmbedder(
            http,
            Microsoft.Extensions.Options.Options.Create(Options(o => o.ApiKey = "hf_token")),
            NullLogger<HttpQueryEmbedder>.Instance);

        await embedder.EmbedAsync("anything");

        Assert.Equal("Bearer", http.DefaultRequestHeaders.Authorization?.Scheme);
        Assert.Equal("hf_token", http.DefaultRequestHeaders.Authorization?.Parameter);
    }

    [Fact]
    public void An_empty_base_url_means_the_embedder_is_not_configured()
    {
        Assert.False(new EmbedderServiceOptions().IsConfigured);
        Assert.True(new EmbedderServiceOptions { BaseUrl = "http://localhost:7860" }.IsConfigured);
    }
}

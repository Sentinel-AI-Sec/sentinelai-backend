using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Infrastructure.Knowledge;

/// <summary>
/// Embeds query text by calling the BGE-M3 service in <c>sentinelai-knowledge/service/</c>
/// (SEC-22).
/// </summary>
/// <remarks>
/// <para>
/// The backend loads no model. The service wraps the same <c>embedder.py</c> the ingest used, so
/// the same-model invariant holds because there is one definition of the model, not because two
/// implementations were kept in step. <c>PIPELINE_A_CONTEXT.md</c> §5 is the reason that matters:
/// a mismatch produces meaningless similarity scores <em>and no error appears</em>.
/// </para>
/// <para>
/// <b>It never falls back.</b> A failed call throws. An embedder that quietly returned something
/// on failure would ground the debate in vectors from nowhere and report success — the same class
/// of failure the ingest's <c>get_embedder</c> refuses by calling <c>sys.exit</c> rather than
/// coping.
/// </para>
/// <para>
/// <b>Sparse survives.</b> That is the whole reason for running our own service rather than a
/// commercial embedding API: those return one dense vector, while this returns BGE-M3's lexical
/// half too, so hybrid search and RRF fusion actually run.
/// </para>
/// </remarks>
public sealed class HttpQueryEmbedder : IQueryEmbedder
{
    private readonly HttpClient _http;
    private readonly EmbedderServiceOptions _options;
    private readonly ILogger<HttpQueryEmbedder> _logger;

    /// <summary>
    /// Whether a request has already succeeded, which decides the timeout for the next one.
    /// </summary>
    /// <remarks>
    /// Not a cache and not thread-sensitive in any way that matters: the worst a race can do is
    /// grant one extra request the longer timeout.
    /// </remarks>
    private bool _warm;

    public HttpQueryEmbedder(
        HttpClient http, IOptions<EmbedderServiceOptions> options, ILogger<HttpQueryEmbedder> logger)
    {
        _options = options.Value;
        _logger = logger;
        _http = http;

        if (!_options.IsConfigured)
        {
            throw new InvalidOperationException(
                "HttpQueryEmbedder was registered without a Knowledge:Embedder:BaseUrl. Configure "
                + "the service URL, or leave it empty so NotConfiguredQueryEmbedder is registered "
                + "instead and the failure is explicit at the call site.");
        }

        _http.BaseAddress = new Uri(_options.BaseUrl.TrimEnd('/') + "/");

        // The per-request timeout is applied with a CancellationToken rather than through
        // HttpClient.Timeout, because the cold-start and warm budgets differ by an order of
        // magnitude and HttpClient.Timeout cannot vary per call.
        _http.Timeout = Timeout.InfiniteTimeSpan;

        if (!string.IsNullOrWhiteSpace(_options.ApiKey))
        {
            _http.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _options.ApiKey);
        }
    }

    public string Model => _options.Model;
    public string Revision => _options.Revision;
    public int DenseDimensions => _options.DenseDimensions;

    /// <summary>True — a service URL is configured, or the constructor would have refused.</summary>
    public bool IsAvailable => true;

    /// <summary>Embeds one query string.</summary>
    /// <exception cref="InvalidOperationException">
    /// The service failed, answered in a shape this cannot read, or returned a vector of the
    /// wrong width.
    /// </exception>
    public async Task<QueryVectors> EmbedAsync(string text, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);

        var response = await PostAsync<EmbedResponse>(
            "embed", new EmbedRequest([text], ReturnSparse: true), Budget, ct);

        if (response.Dense.Count == 0)
        {
            throw new InvalidOperationException(
                "The embedding service returned no dense vector for a query it accepted.");
        }

        var dense = response.Dense[0];

        // The one failure that silently poisons everything downstream. The service checks this
        // too; it is checked again here because the cost is a comparison and the cost of missing
        // it is an audit grounded in vectors the index cannot compare.
        if (dense.Count != DenseDimensions)
        {
            throw new InvalidOperationException(
                $"The embedding service produced {dense.Count}-dimensional vectors but the corpus "
                + $"was indexed at {DenseDimensions}. Refusing to query with vectors the index "
                + "cannot compare.");
        }

        _warm = true;

        var sparse = response.Sparse is { Count: > 0 } ? response.Sparse[0] : null;

        return new QueryVectors(dense, ToSparse(sparse));
    }

    /// <summary>
    /// Loads the model on the service so the first real query does not pay the cold start.
    /// </summary>
    /// <remarks>
    /// Returns false rather than throwing. A sleeping Space at boot is normal and recoverable,
    /// and refusing to start the backend over it would take down the exact-filter arm too, which
    /// needs no embedder at all.
    /// </remarks>
    public async Task<bool> WarmUpAsync(CancellationToken ct = default)
    {
        try
        {
            var result = await PostAsync<WarmUpResponse>(
                "warmup", new { }, TimeSpan.FromSeconds(_options.ColdStartTimeoutSeconds), ct);

            _warm = true;

            _logger.LogInformation(
                "Embedding service at {BaseUrl} is warm ({Seconds}s to load)",
                _options.BaseUrl, result.Seconds);

            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(
                ex,
                "Could not warm the embedding service at {BaseUrl}. The exact-filter arm is "
                + "unaffected; the first semantic query will pay the cold start instead",
                _options.BaseUrl);

            return false;
        }
    }

    /// <summary>
    /// Asserts the service is serving the model the corpus was indexed with.
    /// </summary>
    /// <exception cref="InvalidOperationException">The dimension or the parity norms disagree.</exception>
    /// <remarks>
    /// <para>
    /// <b>A matching dimension is not evidence of a matching model.</b> Plenty of models are
    /// 1024-wide. The norms from <c>parity_check()</c> are the real check, which is why that
    /// function exists — its own docstring says "Record these so the C# side can assert the same
    /// numbers at the boundary (SEC-48)".
    /// </para>
    /// <para>
    /// When no baseline is configured this verifies the width and <em>says in the log</em> that
    /// it verified nothing stronger, rather than reporting a pass that sounds like more than it is.
    /// </para>
    /// </remarks>
    public async Task VerifyParityAsync(CancellationToken ct = default)
    {
        var parity = await GetAsync<ParityResponse>(
            "parity", TimeSpan.FromSeconds(_options.ColdStartTimeoutSeconds), ct);

        _warm = true;

        if (parity.Dim != DenseDimensions)
        {
            throw new InvalidOperationException(
                $"The embedding service serves {parity.Dim}-dimensional vectors but this backend "
                + $"expects {DenseDimensions}. Index-time and query-time vectors must come from "
                + "the same model, or similarity scores are meaningless and nothing errors.");
        }

        if (_options.ExpectedNorms.Length == 0)
        {
            _logger.LogWarning(
                "Embedding service at {BaseUrl} reports {Model} at {Dim} dimensions. No parity "
                + "baseline is configured, so only the width was checked — a different model of "
                + "the same width would pass. Set Knowledge:Embedder:ExpectedNorms from the "
                + "ingest's parity_check() to close that gap",
                _options.BaseUrl, parity.Model, parity.Dim);

            return;
        }

        if (parity.Norms.Count != _options.ExpectedNorms.Length)
        {
            throw new InvalidOperationException(
                $"The parity baseline has {_options.ExpectedNorms.Length} norm(s) but the service "
                + $"returned {parity.Norms.Count}. They come from the same probe list, so a "
                + "different count means the baseline was taken from a different version.");
        }

        for (var i = 0; i < parity.Norms.Count; i++)
        {
            var drift = Math.Abs(parity.Norms[i] - _options.ExpectedNorms[i]);
            if (drift <= _options.ParityTolerance) continue;

            throw new InvalidOperationException(
                $"Parity probe {i} drifted by {drift:G6}, over the {_options.ParityTolerance:G6} "
                + $"tolerance (corpus {_options.ExpectedNorms[i]:G9}, service {parity.Norms[i]:G9}). "
                + "GPU-versus-CPU rounding does not move these numbers this far; a different model "
                + "does. Refusing to query a corpus this embedder did not build.");
        }

        _logger.LogInformation(
            "Embedding service at {BaseUrl} matches the corpus: {Model}, {Dim} dimensions, "
            + "{Probes} parity probe(s) within {Tolerance}",
            _options.BaseUrl, parity.Model, parity.Dim, parity.Norms.Count, _options.ParityTolerance);
    }

    /// <summary>The cold-start budget until something has succeeded, then the warm one.</summary>
    private TimeSpan Budget => TimeSpan.FromSeconds(
        _warm ? _options.TimeoutSeconds : _options.ColdStartTimeoutSeconds);

    private static SparseQueryVector? ToSparse(SparseDto? dto)
    {
        // Null and empty are both "no lexical half". Modelling them the same way here is what
        // stops an empty sparse prefetch — which matches nothing — being sent as if it were real.
        if (dto is null || dto.Indices.Count == 0) return null;

        return SparseQueryVector.Create(dto.Indices, dto.Values);
    }

    private Task<T> PostAsync<T>(string path, object body, TimeSpan budget, CancellationToken ct) =>
        SendAsync<T>(path, budget, ct, token => _http.PostAsJsonAsync(path, body, token));

    private Task<T> GetAsync<T>(string path, TimeSpan budget, CancellationToken ct) =>
        SendAsync<T>(path, budget, ct, token => _http.GetAsync(path, token));

    /// <summary>
    /// One request, with the per-call budget applied and every failure turned into one message
    /// that names the service.
    /// </summary>
    /// <remarks>
    /// A bare <c>HttpRequestException</c> from deep in a scan says "connection refused" and
    /// nothing about which of several external services refused it.
    /// </remarks>
    private async Task<T> SendAsync<T>(
        string path, TimeSpan budget, CancellationToken ct, Func<CancellationToken, Task<HttpResponseMessage>> send)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(budget);

        HttpResponseMessage response;
        try
        {
            response = await send(timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new InvalidOperationException(
                $"The embedding service at {_options.BaseUrl} did not answer /{path} within "
                + $"{budget.TotalSeconds:0}s. A free Space that has slept can take minutes to "
                + "wake; raise Knowledge:Embedder:ColdStartTimeoutSeconds if that is the cause.");
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"Could not reach the embedding service at {_options.BaseUrl}/{path}: {ex.Message}", ex);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                var detail = await SafeReadAsync(response, timeout.Token);

                throw new InvalidOperationException(
                    $"The embedding service at {_options.BaseUrl} answered /{path} with "
                    + $"{(int)response.StatusCode} {response.ReasonPhrase}. {detail}".TrimEnd());
            }

            var value = await response.Content.ReadFromJsonAsync<T>(timeout.Token);

            return value ?? throw new InvalidOperationException(
                $"The embedding service at {_options.BaseUrl} answered /{path} with a body this "
                + "backend could not read as the expected shape.");
        }
    }

    private static async Task<string> SafeReadAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            return body.Length > 400 ? body[..400] : body;
        }
        catch
        {
            // The status code is the useful half; a body that will not read must not replace it
            // with an exception about reading bodies.
            return string.Empty;
        }
    }

    // ---- the service's wire shapes ---------------------------------------------------------

    private sealed record EmbedRequest(
        [property: JsonPropertyName("texts")] IReadOnlyList<string> Texts,
        [property: JsonPropertyName("return_sparse")] bool ReturnSparse);

    private sealed record EmbedResponse(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("dim")] int Dim,
        [property: JsonPropertyName("dense")] IReadOnlyList<IReadOnlyList<float>> Dense,
        [property: JsonPropertyName("sparse")] IReadOnlyList<SparseDto?>? Sparse);

    private sealed record SparseDto(
        [property: JsonPropertyName("indices")] IReadOnlyList<uint> Indices,
        [property: JsonPropertyName("values")] IReadOnlyList<float> Values);

    private sealed record WarmUpResponse(
        [property: JsonPropertyName("status")] string Status,
        [property: JsonPropertyName("seconds")] double Seconds);

    private sealed record ParityResponse(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("dim")] int Dim,
        [property: JsonPropertyName("sparse")] bool Sparse,
        [property: JsonPropertyName("norms")] IReadOnlyList<double> Norms,
        [property: JsonPropertyName("checksum")] IReadOnlyList<double> Checksum);
}

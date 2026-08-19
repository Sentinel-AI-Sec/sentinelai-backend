namespace SentinelAI.Infrastructure.Knowledge;

/// <summary>
/// Where the query-embedding service lives, and what it is expected to be.
/// </summary>
/// <remarks>
/// <para>
/// Bound from <c>Knowledge:Embedder</c>. The service is the one in
/// <c>sentinelai-knowledge/service/</c> — it wraps the same <c>embedder.py</c> the ingest used,
/// so query-time and index-time vectors come from one definition of the model rather than two.
/// </para>
/// <para>
/// Leave <see cref="BaseUrl"/> empty and no embedder is registered: the exact-filter arm still
/// grounds every finding carrying a clean CVE or CWE, and the semantic arm fails naming the
/// reason. That is deliberate — see <see cref="NotConfiguredQueryEmbedder"/>.
/// </para>
/// </remarks>
public sealed class EmbedderServiceOptions
{
    public const string SectionName = "Knowledge:Embedder";

    /// <summary>
    /// Root URL of the service, e.g. <c>http://localhost:7860</c> or a Space's
    /// <c>https://user-space.hf.space</c>.
    /// </summary>
    public string BaseUrl { get; set; } = string.Empty;

    /// <summary>Bearer token. Needed for a private HuggingFace Space; empty locally.</summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>What the service is expected to be serving. Checked against its own answer.</summary>
    public string Model { get; set; } = "BAAI/bge-m3";

    /// <summary>The pinned revision the corpus was indexed at.</summary>
    public string Revision { get; set; } = "5617a9f61b028005a4858fdac845db406aefb181";

    /// <summary>Dense width. Must match what the collections were created with.</summary>
    public int DenseDimensions { get; set; } = 1024;

    /// <summary>Timeout for a normal, warm request.</summary>
    public int TimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Timeout for the first request, and for <c>/warmup</c>.
    /// </summary>
    /// <remarks>
    /// A free HuggingFace Space sleeps after about 48 hours idle. Waking one costs a container
    /// start plus loading 2.2 GB of weights on CPU — minutes, not seconds. A single timeout
    /// tuned for warm requests turns the first scan after a quiet weekend into an outage; one
    /// tuned for cold starts makes every genuine failure take five minutes to report. Hence two.
    /// </remarks>
    public int ColdStartTimeoutSeconds { get; set; } = 300;

    /// <summary>
    /// Call <c>/warmup</c> at startup so the first real query does not pay the cold start.
    /// </summary>
    /// <remarks>
    /// Failures are logged, not thrown. The service being asleep at boot is normal and
    /// recoverable; refusing to start the whole backend over it would take down the exact-filter
    /// arm too, which does not need the embedder at all.
    /// </remarks>
    public bool WarmUpOnStartup { get; set; } = true;

    /// <summary>
    /// The <c>norms</c> from <c>parity_check()</c>, recorded during ingest.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Optional, and the only real evidence that query-time and index-time are the same model.
    /// A matching dimension is not evidence — plenty of models are 1024-wide. Leave it empty and
    /// only the width is checked, which is stated in the log rather than implied.
    /// </para>
    /// <para>
    /// Produce it on the machine that embedded the corpus:
    /// <c>parity_check(get_embedder('bge', model=..., revision=..., dims=1024))["norms"]</c>.
    /// </para>
    /// </remarks>
    public double[] ExpectedNorms { get; set; } = [];

    /// <summary>
    /// How far a norm may drift before parity is treated as broken.
    /// </summary>
    /// <remarks>
    /// Index time ran on GPU and query time runs on CPU, so the same model does not produce
    /// bit-identical floats. It produces very close ones: the tolerance is here to absorb that
    /// difference, not to be widened until a mismatch passes. A genuinely different model moves
    /// these numbers far more than this.
    /// </remarks>
    public double ParityTolerance { get; set; } = 1e-3;

    /// <summary>True when a service URL has been configured.</summary>
    public bool IsConfigured => !string.IsNullOrWhiteSpace(BaseUrl);
}

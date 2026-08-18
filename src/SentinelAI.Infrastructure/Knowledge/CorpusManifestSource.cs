using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Infrastructure.Knowledge;

/// <summary>
/// Where the corpus manifest lives for this deployment.
/// </summary>
/// <remarks>
/// Bound from <c>Knowledge:Manifest</c>. Both keys are optional: with neither set the boundary is
/// reported as unproven, which is the honest description of a deployment that has not published
/// one.
/// </remarks>
public sealed class CorpusManifestOptions
{
    public const string SectionName = "Knowledge:Manifest";

    /// <summary>
    /// Path to the JSON <c>sentinelai-knowledge</c> writes, e.g.
    /// <c>../sentinelai-knowledge/out/corpus_manifest.json</c>.
    /// </summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// Fail startup when the manifest and the embedder disagree in a way that is known-wrong.
    /// </summary>
    /// <remarks>
    /// On by default, and it should stay on. The failure it prevents is the one
    /// <c>PIPELINE_A_CONTEXT.md</c> §5 calls out as producing "meaningless results and no error" —
    /// booting anyway means every audit from that deployment cites vectors from nowhere.
    /// </remarks>
    public bool FailFastOnMismatch { get; set; } = true;
}

/// <summary>
/// Reads Pipeline A's <c>corpus_manifest.json</c> off disk (SEC-48).
/// </summary>
/// <remarks>
/// <para>
/// Read once and cached: the manifest describes a corpus that was built before this process
/// started and cannot change under it. Re-reading per scan would add file IO to the hot path to
/// detect something that would require a redeploy anyway.
/// </para>
/// <para>
/// <b>A malformed or missing manifest returns null rather than throwing.</b> "No manifest" and
/// "unreadable manifest" both mean the boundary is unproven, and that is a state the system
/// already handles — whereas throwing here would take down a deployment whose exact-filter arm
/// works perfectly well.
/// </para>
/// </remarks>
public sealed class FileCorpusManifestSource(
    IOptions<CorpusManifestOptions> options,
    ILogger<FileCorpusManifestSource> logger) : ICorpusManifestSource
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private CorpusManifest? _cached;
    private bool _read;

    public async Task<CorpusManifest?> GetAsync(CancellationToken ct = default)
    {
        if (_read) return _cached;

        await _gate.WaitAsync(ct);

        try
        {
            if (_read) return _cached;

            _cached = Read(options.Value.Path);
            _read = true;

            return _cached;
        }
        finally
        {
            _gate.Release();
        }
    }

    private CorpusManifest? Read(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            logger.LogInformation(
                "No corpus manifest is configured (Knowledge:Manifest:Path). The A-to-B boundary "
                + "will be reported as unproven rather than verified");

            return null;
        }

        var full = System.IO.Path.GetFullPath(path);

        if (!File.Exists(full))
        {
            logger.LogWarning(
                "Corpus manifest not found at {Path}. Run an ingest in sentinelai-knowledge, or "
                + "clear Knowledge:Manifest:Path if this deployment has no manifest", full);

            return null;
        }

        try
        {
            var dto = JsonSerializer.Deserialize<ManifestDto>(File.ReadAllText(full));

            if (dto?.Embedding is null || string.IsNullOrWhiteSpace(dto.CorpusVersion))
            {
                logger.LogWarning(
                    "Corpus manifest at {Path} has no corpus_version or no embedding block; it is "
                    + "probably a dry run. Treating the boundary as unproven", full);

                return null;
            }

            var manifest = new CorpusManifest
            {
                CorpusVersion = dto.CorpusVersion,
                Model = dto.Embedding.Model ?? string.Empty,
                Revision = string.IsNullOrWhiteSpace(dto.Embedding.Revision) ? null : dto.Embedding.Revision,
                DenseDimensions = dto.Embedding.DenseDim,
                Sparse = dto.Parity?.Sparse ?? true,
                ParityNorms = dto.Parity?.Norms ?? [],
            };

            logger.LogInformation(
                "Corpus manifest {Version}: {Model} @ {Revision}, {Dim}-dim, {Norms} parity norm(s)",
                manifest.CorpusVersion, manifest.Model, manifest.Revision ?? "unpinned",
                manifest.DenseDimensions, manifest.ParityNorms.Count);

            return manifest;
        }
        catch (JsonException e)
        {
            logger.LogWarning(
                "Corpus manifest at {Path} could not be parsed ({Error}). Treating the boundary as "
                + "unproven", full, e.Message);

            return null;
        }
    }

    /// <summary>
    /// The shape <c>sentinelai_knowledge/manifest.py</c> writes.
    /// </summary>
    /// <remarks>
    /// Snake-case names, matching the Python side verbatim. These are cross-repo strings in two
    /// languages — the same hazard <c>CorpusWire</c> exists to contain — so they are named once
    /// here rather than being spelled out at each read.
    /// </remarks>
    private sealed record ManifestDto
    {
        [JsonPropertyName("corpus_version")] public string? CorpusVersion { get; init; }
        [JsonPropertyName("embedding")] public EmbeddingDto? Embedding { get; init; }
        [JsonPropertyName("parity")] public ParityDto? Parity { get; init; }
    }

    private sealed record EmbeddingDto
    {
        [JsonPropertyName("model")] public string? Model { get; init; }
        [JsonPropertyName("revision")] public string? Revision { get; init; }
        [JsonPropertyName("dense_dim")] public int DenseDim { get; init; }
    }

    private sealed record ParityDto
    {
        [JsonPropertyName("norms")] public IReadOnlyList<double>? Norms { get; init; }
        [JsonPropertyName("sparse")] public bool? Sparse { get; init; }
    }
}

/// <summary>
/// A manifest supplied directly by configuration, for a deployment with no file to read.
/// </summary>
/// <remarks>
/// The case this exists for: a backend pointed at a cluster a teammate filled, where the corpus is
/// real but the ingest ran somewhere else entirely. Copying four values into settings is weaker
/// evidence than reading the file the ingest wrote — it is two people agreeing rather than one
/// measurement — but it is much stronger than nothing, and it is the difference between a checked
/// boundary and an assumed one.
/// </remarks>
public sealed class ConfiguredCorpusManifestSource(CorpusManifest manifest) : ICorpusManifestSource
{
    public Task<CorpusManifest?> GetAsync(CancellationToken ct = default) =>
        Task.FromResult<CorpusManifest?>(manifest);
}

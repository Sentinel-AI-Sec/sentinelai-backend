using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Infrastructure.Implementation.Repositories;
using SentinelAI.Infrastructure.Knowledge;

namespace SentinelAI.Infrastructure.Tests.Knowledge;

/// <summary>
/// SEC-48's infrastructure half: reading Pipeline A's manifest, and refusing to run against a
/// corpus this deployment cannot prove it matches.
/// </summary>
/// <remarks>
/// <see cref="SentinelAI.Application.Tests"/> owns the invariant itself, which is pure. These
/// cover the parts that touch the world — a JSON file written by another repository in another
/// language, and the decision to stop a boot.
/// </remarks>
public class CorpusBoundaryTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sentinelai-manifest").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    private string WriteManifest(string json)
    {
        var path = Path.Combine(_dir, "corpus_manifest.json");
        File.WriteAllText(path, json);
        return path;
    }

    private static FileCorpusManifestSource SourceFor(string path) => new(
        Options.Create(new CorpusManifestOptions { Path = path }),
        NullLogger<FileCorpusManifestSource>.Instance);

    /// <summary>The shape <c>sentinelai_knowledge/manifest.py</c> actually writes.</summary>
    private const string RealManifest = """
    {
      "corpus_version": "2026-08-10-1143",
      "built_at": "2026-08-10T11:43:02+00:00",
      "embedding": {
        "model": "BAAI/bge-m3",
        "revision": "5617a9f61b028005a4858fdac845db406aefb181",
        "dense_dim": 1024,
        "use_fp16": false
      },
      "parity": {
        "backend": "bge",
        "dim": 1024,
        "sparse": true,
        "norms": [17.482134, 19.203311, 18.057702]
      },
      "chunks": { "total": 32432 }
    }
    """;

    private sealed class Embedder(
        string model = "BAAI/bge-m3",
        string revision = "5617a9f61b028005a4858fdac845db406aefb181",
        int dims = 1024) : IQueryEmbedder
    {
        public string Model { get; } = model;
        public string Revision { get; } = revision;
        public int DenseDimensions { get; } = dims;
        public bool IsAvailable => true;

        public Task<QueryVectors> EmbedAsync(string text, CancellationToken ct = default) =>
            throw new NotSupportedException();
    }

    private CorpusBoundaryGuard Guard(
        ICorpusManifestSource source, IQueryEmbedder embedder, bool failFast = true) => new(
            source, embedder,
            Options.Create(new CorpusManifestOptions { FailFastOnMismatch = failFast }),
            NullLogger<CorpusBoundaryGuard>.Instance);

    // ---- reading the manifest -------------------------------------------------------------------

    [Fact]
    public async Task The_manifest_pipeline_a_writes_is_read_field_for_field()
    {
        var manifest = await SourceFor(WriteManifest(RealManifest)).GetAsync();

        Assert.NotNull(manifest);
        Assert.Equal("2026-08-10-1143", manifest.CorpusVersion);
        Assert.Equal("BAAI/bge-m3", manifest.Model);
        Assert.Equal("5617a9f61b028005a4858fdac845db406aefb181", manifest.Revision);
        Assert.Equal(1024, manifest.DenseDimensions);
        Assert.Equal(3, manifest.ParityNorms.Count);
        Assert.True(manifest.HasPinnedRevision);
        Assert.True(manifest.HasParityBaseline);
    }

    [Fact]
    public async Task No_configured_path_means_no_manifest_rather_than_a_crash()
    {
        Assert.Null(await SourceFor(string.Empty).GetAsync());
    }

    [Fact]
    public async Task A_missing_file_means_no_manifest_rather_than_a_crash()
    {
        Assert.Null(await SourceFor(Path.Combine(_dir, "absent.json")).GetAsync());
    }

    [Fact]
    public async Task Malformed_json_is_treated_as_unproven_not_fatal()
    {
        // A deployment whose exact-filter arm works perfectly well should not be taken down by a
        // truncated sidecar file.
        Assert.Null(await SourceFor(WriteManifest("{ not json")).GetAsync());
    }

    /// <summary>
    /// The dry-run manifest that is actually sitting in the repo today.
    /// </summary>
    /// <remarks>
    /// <c>out/corpus_manifest.json</c> currently records zero chunks and a null revision, because
    /// it was written by a run that never embedded anything. Reading that as a real manifest would
    /// let a corpus be "verified" against a build that did not happen.
    /// </remarks>
    [Fact]
    public async Task A_dry_run_manifest_with_no_corpus_version_is_rejected()
    {
        var manifest = await SourceFor(WriteManifest("""
        { "corpus_version": "", "embedding": { "model": "BAAI/bge-m3", "dense_dim": 1024 } }
        """)).GetAsync();

        Assert.Null(manifest);
    }

    [Fact]
    public async Task A_manifest_with_a_null_revision_loads_but_stays_unpinned()
    {
        var manifest = await SourceFor(WriteManifest("""
        {
          "corpus_version": "2026-08-14-2010",
          "embedding": { "model": "BAAI/bge-m3", "revision": null, "dense_dim": 1024 }
        }
        """)).GetAsync();

        Assert.NotNull(manifest);
        Assert.False(manifest.HasPinnedRevision);
        Assert.False(manifest.HasParityBaseline);
    }

    [Fact]
    public async Task The_manifest_is_read_once_and_cached()
    {
        var path = WriteManifest(RealManifest);
        var source = SourceFor(path);

        var first = await source.GetAsync();
        File.Delete(path);                       // it describes a corpus built before this process
        var second = await source.GetAsync();

        Assert.NotNull(second);
        Assert.Equal(first!.CorpusVersion, second.CorpusVersion);
    }

    // ---- the guard --------------------------------------------------------------------------------

    [Fact]
    public async Task A_matching_pair_passes_and_reports_nothing_wrong()
    {
        var guard = Guard(SourceFor(WriteManifest(RealManifest)), new Embedder());

        Assert.Empty(await guard.VerifyAsync());
    }

    /// <summary>
    /// The one that matters: a known-wrong pairing stops the host instead of producing meaningless
    /// results for the rest of the deployment's life.
    /// </summary>
    [Fact]
    public async Task A_revision_mismatch_refuses_to_start()
    {
        var guard = Guard(
            SourceFor(WriteManifest(RealManifest)),
            new Embedder(revision: "0000000000000000000000000000000000000000"));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => guard.VerifyAsync());

        Assert.Contains("not the same pairing", error.Message, StringComparison.Ordinal);
        Assert.Contains("2026-08-10-1143", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_model_mismatch_refuses_to_start()
    {
        var guard = Guard(
            SourceFor(WriteManifest(RealManifest)), new Embedder(model: "intfloat/e5-large-v2"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => guard.VerifyAsync());
    }

    [Fact]
    public async Task Fail_fast_can_be_turned_off_for_a_deployment_that_knows_better()
    {
        var guard = Guard(
            SourceFor(WriteManifest(RealManifest)),
            new Embedder(model: "intfloat/e5-large-v2"),
            failFast: false);

        var mismatches = await guard.VerifyAsync();

        Assert.False(mismatches.IsUsable());     // still reported as wrong
        Assert.NotEmpty(mismatches);             // just not thrown
    }

    [Fact]
    public async Task No_manifest_is_unverified_rather_than_failed()
    {
        var guard = Guard(SourceFor(string.Empty), new Embedder());

        Assert.Empty(await guard.VerifyAsync());
    }

    // ---- the version stamp source -------------------------------------------------------------------

    [Fact]
    public async Task The_scan_stamp_comes_from_the_manifest_when_there_is_one()
    {
        var provider = new ManifestCorpusVersionProvider(
            SourceFor(WriteManifest(RealManifest)),
            Options.Create(new CorpusOptions { Version = "unversioned" }),
            NullLogger<ManifestCorpusVersionProvider>.Instance);

        Assert.Equal("2026-08-10-1143", await provider.GetCurrentVersionAsync(default));
    }

    [Fact]
    public async Task The_scan_stamp_falls_back_to_configuration_when_there_is_not()
    {
        var provider = new ManifestCorpusVersionProvider(
            SourceFor(string.Empty),
            Options.Create(new CorpusOptions { Version = "local-dev" }),
            NullLogger<ManifestCorpusVersionProvider>.Instance);

        Assert.Equal("local-dev", await provider.GetCurrentVersionAsync(default));
    }
}

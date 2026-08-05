using System.Formats.Tar;
using System.IO.Compression;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentinelAI.Domain.Abstractions.Repositories;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

/// <summary>Job-scoped directory on disk. Good enough for the POC and for Compose.</summary>
/// <remarks>
/// Behind <see cref="IBundleStore"/> precisely so swapping in blob storage later is a DI
/// change. <see cref="PurgeAsync"/> is what SEC-29 calls when retention runs.
/// </remarks>
public sealed class FileSystemBundleStore(
    IOptions<BundleStorageOptions> options,
    ILogger<FileSystemBundleStore> logger) : IBundleStore
{
    private readonly BundleStorageOptions _options = options.Value;
 
    public async Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct)
    {
        var dir = Path.Combine(_options.RootPath, scanJobId.ToString());
        Directory.CreateDirectory(dir);
 
        var path = Path.Combine(dir, "bundle.tar.gz");
 
        if (bundle.CanSeek) bundle.Position = 0;
        await using var file = File.Create(path);
        await bundle.CopyToAsync(file, ct);
 
        logger.LogInformation("Stored bundle for job {JobId} at {Path}", scanJobId, path);
        return path;
    }
 
    /// <summary>The findings the scanners produced live under this prefix inside the bundle.</summary>
    private const string FindingsPrefix = "findings/";

    public async Task<IReadOnlyList<StoredBundleFile>> OpenFindingsAsync(string locator, CancellationToken ct)
    {
        // The locator is the path SaveAsync returned — the job's bundle.tar.gz.
        if (!File.Exists(locator))
        {
            logger.LogWarning("Bundle locator {Locator} no longer exists (purged?)", locator);
            return [];
        }

        var findings = new List<StoredBundleFile>();

        await using var file = File.OpenRead(locator);
        await using var gzip = new GZipStream(file, CompressionMode.Decompress);
        await using var tar = new TarReader(gzip, leaveOpen: false);

        while (await tar.GetNextEntryAsync(cancellationToken: ct) is { } entry)
        {
            if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile))
                continue;

            var name = Normalize(entry.Name);
            if (!name.StartsWith(FindingsPrefix, StringComparison.OrdinalIgnoreCase) || entry.DataStream is null)
                continue;

            using var buffer = new MemoryStream();
            await entry.DataStream.CopyToAsync(buffer, ct);
            findings.Add(new StoredBundleFile(name, buffer.ToArray()));
        }

        logger.LogInformation("Opened {Count} findings file(s) from {Locator}", findings.Count, locator);
        return findings;
    }

    /// <summary>Tar writes a leading <c>./</c>; strip it so the prefix check is like-for-like.</summary>
    private static string Normalize(string name) => name.Replace('\\', '/').TrimStart('.', '/');

    public Task PurgeAsync(Guid scanJobId, CancellationToken ct)
    {
        var dir = Path.Combine(_options.RootPath, scanJobId.ToString());
        if (Directory.Exists(dir))
        {
            Directory.Delete(dir, recursive: true);
            logger.LogInformation("Purged bundle storage for job {JobId}", scanJobId);
        }
        return Task.CompletedTask;
    }
}
 
public sealed class BundleStorageOptions
{
    public const string SectionName = "BundleStorage";
    public string RootPath { get; set; } = "/var/sentinelai/bundles";
}
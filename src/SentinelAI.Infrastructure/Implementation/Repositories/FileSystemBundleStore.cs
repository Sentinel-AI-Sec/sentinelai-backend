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
namespace SentinelAI.Domain.Abstractions.Repositories;

/// <summary>
/// Where a received bundle lives between ingest and the worker that consumes it.
/// </summary>
/// <remarks>
/// Deliberately an interface: the POC writes to a job-scoped directory on disk, but
/// retention (SEC-29) means "purge after audit" has to be a single call, and a blob
/// backend later must not ripple into the handler.
/// </remarks>
public interface IBundleStore
{
    /// <summary>Persists the bundle for a job and returns an opaque locator.</summary>
    Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct);

    /// <summary>
    /// Reads back the bundle's <c>findings/</c> files for the normalization stage, given the
    /// locator <see cref="SaveAsync"/> returned. Only the store knows how to interpret its own
    /// locator, so the read-back lives here rather than a caller re-deriving a path — that is
    /// what keeps the locator genuinely opaque.
    /// </summary>
    /// <remarks>
    /// Returns only the findings files (SARIF/JSON the scanners produced); graph inputs and
    /// metadata are not the normalizer's concern. The bundle is small (capped at ingest), so
    /// each file is materialized into memory rather than streamed lazily.
    /// </remarks>
    Task<IReadOnlyList<StoredBundleFile>> OpenFindingsAsync(string locator, CancellationToken ct);

    /// <summary>Deletes everything held for a job. Idempotent.</summary>
    Task PurgeAsync(Guid scanJobId, CancellationToken ct);
}

/// <summary>One file read back out of a stored bundle.</summary>
/// <param name="Name">Bundle-root-relative path, e.g. <c>findings/roslyn.sarif</c>.</param>
/// <param name="Content">The decompressed bytes of the file.</param>
public sealed record StoredBundleFile(string Name, byte[] Content);

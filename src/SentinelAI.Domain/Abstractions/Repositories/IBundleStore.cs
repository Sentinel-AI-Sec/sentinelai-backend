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
 
    /// <summary>Deletes everything held for a job. Idempotent.</summary>
    Task PurgeAsync(Guid scanJobId, CancellationToken ct);
}
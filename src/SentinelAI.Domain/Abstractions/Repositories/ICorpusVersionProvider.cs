namespace SentinelAI.Domain.Abstractions.Repositories;

/// <summary>
/// Which snapshot of the Qdrant knowledge corpus a scan will retrieve against.
/// </summary>
/// <remarks>
/// Stamped on the job at accept time, not at retrieval time, so an audit can always be
/// reproduced against the corpus it actually saw (SEC-41). Until Pipeline A publishes a
/// real version this returns a configured constant — the field exists from day one so
/// nothing has to be retrofitted.
/// </remarks>
public interface ICorpusVersionProvider
{
    Task<string> GetCurrentVersionAsync(CancellationToken ct);
}
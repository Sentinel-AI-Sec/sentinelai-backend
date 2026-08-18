using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Application.Abstractions;

/// <summary>
/// Where this deployment reads Pipeline A's published corpus manifest from (SEC-48).
/// </summary>
/// <remarks>
/// <para>
/// A port, because the manifest travels differently in different deployments: a file beside a
/// local ingest, a value baked into configuration for a cluster someone else filled, and
/// eventually the corpus itself. What SEC-48 asserts does not change with the transport, so the
/// assertion lives in <see cref="CorpusParity"/> and the fetching lives here.
/// </para>
/// <para>
/// <b>Null is a real answer.</b> A deployment pointed at a corpus whose manifest was never
/// published is a supported state — it is how every environment looked before this story — and it
/// is reported as unproven rather than crashed. What is not supported is treating that state as
/// verified.
/// </para>
/// </remarks>
public interface ICorpusManifestSource
{
    /// <summary>The manifest, or null when this deployment has none.</summary>
    Task<CorpusManifest?> GetAsync(CancellationToken ct = default);
}

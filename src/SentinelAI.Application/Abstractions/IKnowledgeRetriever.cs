using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Abstractions;

/// <summary>
/// Grounds one finding in the knowledge corpus. Application says WHAT it needs; the
/// implementation says HOW.
/// </summary>
/// <remarks>
/// <para>
/// <b>It takes the finding, not a query string, and that is what makes SEC-22 reachable.</b> The
/// original seam passed pre-built text, which is enough for a meaning-based search and useless for
/// the exact one: an id lookup needs <see cref="Finding.CweId"/> and <see cref="Finding.CveId"/>
/// as values to filter on, not as words inside a sentence. Recovering them by parsing the query
/// back apart would re-invent <see cref="IdentifierFormats"/> at the far end of the seam, and the
/// exact arm is the first thing SEC-22 promises.
/// </para>
/// <para>
/// Two implementations, chosen by configuration rather than by code:
/// <see cref="KnowledgeRetrievalService"/> when a corpus is configured, and the canned-answer
/// stub when one is not — which is what keeps the walking skeleton and the offline demo running
/// on a machine with no Qdrant and no embedding service.
/// </para>
/// </remarks>
public interface IKnowledgeRetriever
{
    /// <summary>
    /// Retrieves the knowledge supporting one finding.
    /// </summary>
    /// <param name="finding">A unified finding from SEC-16.</param>
    /// <param name="intent">What is being asked, which fixes the collection and the mandatory filter.</param>
    /// <param name="ct">Cancellation.</param>
    /// <returns>
    /// What was found and which arm answered — never null. An empty result is a real answer and
    /// means the corpus has nothing for this finding, which callers must handle: the real
    /// retriever returns empty too.
    /// </returns>
    Task<RetrievalResult> RetrieveAsync(
        Finding finding, RetrievalIntent intent, CancellationToken ct = default);
}

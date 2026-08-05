using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Abstractions;

/// <summary>
/// Reads one scanner tool's raw output file and converts it into the canonical
/// <see cref="Finding"/> shape (SEC-14). Each tool speaks a slightly different dialect —
/// SARIF v1, SARIF v2, or a native JSON — and every implementation is the translator for
/// exactly one of them.
/// </summary>
/// <remarks>
/// The extractor never builds a <see cref="Finding.NodeRef"/>: that is a node key, and node
/// keys come only from <c>NodeId</c> at the graph stage. Concatenating one here would be the
/// silent-island bug SEC-03 exists to prevent, so <see cref="Finding.NodeRef"/> is left empty
/// and filled in later.
/// </remarks>
public interface IFindingExtractor
{
    /// <summary>
    /// The tool this extractor understands, e.g. <see cref="ScannerNames.Roslyn"/>. It is both
    /// the value stamped onto every <see cref="Finding.SourceTool"/> and the key the
    /// normalization pipeline uses to route a findings file to the right extractor.
    /// </summary>
    string SourceTool { get; }

    /// <summary>
    /// Parses one findings file into zero or more <see cref="Finding"/> objects.
    /// </summary>
    /// <param name="fileContent">The decompressed bytes of a single findings file.</param>
    /// <param name="tenantId">Owning tenant, stamped onto every finding.</param>
    /// <param name="scanJobId">Owning scan job, stamped onto every finding.</param>
    /// <exception cref="FindingExtractionException">
    /// The input is not valid JSON / SARIF. Missing or unexpected <em>fields</em> are tolerated
    /// (they yield fewer findings); only genuinely unreadable input throws.
    /// </exception>
    IEnumerable<Finding> Extract(Stream fileContent, Guid tenantId, Guid scanJobId);
}

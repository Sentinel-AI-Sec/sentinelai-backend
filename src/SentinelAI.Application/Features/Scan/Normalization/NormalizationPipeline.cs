using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Normalization;

/// <summary>
/// The Normalize stage (SEC-14 + SEC-15): reads a stored bundle's findings files, runs each
/// through the extractor for its tool, resolves any missing CWE from the rule-mapping table,
/// and returns one combined list of canonical <see cref="Finding"/>s.
/// </summary>
/// <remarks>
/// It depends only on the <see cref="IFindingExtractor"/> abstraction and the
/// <see cref="IBundleStore"/> locator — it never touches SARIF or JSON itself, so adding or
/// swapping a tool is a change in Infrastructure, not here. One unreadable file costs that
/// file's findings and nothing else, the same graceful degradation the runner applies when a
/// scanner misbehaves.
/// </remarks>
public sealed class NormalizationPipeline(
    IEnumerable<IFindingExtractor> extractors,
    IBundleStore bundleStore,
    RuleMappingResolver ruleMappings,
    ILogger<NormalizationPipeline> logger)
{
    // How a findings file name maps to a tool: its prefix, and the extension that tool emits.
    // The extension is what keeps osv.sarif (which we deliberately do not read) from reaching
    // the JSON extractor, and only osv.json through.
    private static readonly (string Prefix, string Extension, string Tool)[] Routes =
    [
        ("roslyn", ".sarif", ScannerNames.Roslyn),
        ("osv", ".json", ScannerNames.Osv),
        ("trivy", ".sarif", ScannerNames.Trivy),
        ("checkov", ".sarif", ScannerNames.Checkov),
    ];

    private readonly Dictionary<string, IFindingExtractor> _byTool =
        extractors.ToDictionary(e => e.SourceTool, StringComparer.OrdinalIgnoreCase);

    public async Task<IReadOnlyList<Finding>> NormalizeAsync(
        string bundleLocator, Guid tenantId, Guid scanJobId, CancellationToken ct)
    {
        var files = await bundleStore.OpenFindingsAsync(bundleLocator, ct);
        var findings = new List<Finding>();

        foreach (var file in files)
        {
            var extractor = ResolveExtractor(file.Name);
            if (extractor is null)
            {
                logger.LogDebug("No extractor for findings file {File} — skipping", file.Name);
                continue;
            }

            try
            {
                using var stream = new MemoryStream(file.Content, writable: false);
                findings.AddRange(extractor.Extract(stream, tenantId, scanJobId));
            }
            catch (FindingExtractionException ex)
            {
                // Degrade gracefully: log the bad file, keep the other tools' findings.
                logger.LogWarning(ex, "Could not normalize {File}; skipping it", file.Name);
            }
        }

        // SEC-15: close the CWE gaps before the findings leave this stage. Everything
        // downstream — the RAG exact filter, the graph decoration, the chain hops — joins on
        // the linking key, so a finding that leaves here without one is invisible to all of it.
        // Placed after extraction rather than inside it on purpose: the extractors are pure,
        // synchronous parsers with no database, and one batched lookup for the whole bundle
        // beats a query per result.
        await ruleMappings.ResolveAsync(findings, ct);

        logger.LogInformation(
            "Normalized {Count} finding(s) from {Files} file(s) for job {JobId}; {Unlinked} still carry no CWE or CVE",
            findings.Count, files.Count, scanJobId,
            findings.Count(f => string.IsNullOrWhiteSpace(f.CweId) && string.IsNullOrWhiteSpace(f.CveId)));

        return findings;
    }

    private IFindingExtractor? ResolveExtractor(string fileName)
    {
        var leaf = Path.GetFileName(fileName);
        foreach (var (prefix, extension, tool) in Routes)
        {
            if (leaf.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                leaf.EndsWith(extension, StringComparison.OrdinalIgnoreCase) &&
                _byTool.TryGetValue(tool, out var extractor))
            {
                return extractor;
            }
        }

        return null;
    }
}

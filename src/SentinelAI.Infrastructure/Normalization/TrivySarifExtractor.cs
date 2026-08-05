using System.Text.RegularExpressions;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// Normalizes Trivy SARIF. Trivy straddles two layers in one file: a vulnerability result
/// carries a CVE and belongs to the dependency layer, while a misconfiguration result does not
/// and belongs to infrastructure.
/// </summary>
public sealed partial class TrivySarifExtractor : IFindingExtractor
{
    public string SourceTool => ScannerNames.Trivy;

    public IEnumerable<Finding> Extract(Stream fileContent, Guid tenantId, Guid scanJobId)
    {
        var findings = new List<Finding>();
        foreach (var result in SarifReader.Read(fileContent))
        {
            // A CVE means this is a dependency vulnerability; anything else is a config check.
            var layer = result.CveId is not null ? Layer.Dep : Layer.Infra;
            var finding = SarifFindings.From(result, SourceTool, layer, tenantId, scanJobId);

            if (layer == Layer.Dep && PackageCoordinate(result.Message) is { } coordinate)
                finding.Location = coordinate;

            findings.Add(finding);
        }

        return findings;
    }

    /// <summary>
    /// The <c>name@version</c> Trivy states in a vulnerability message, or null if it did not.
    /// </summary>
    /// <remarks>
    /// A dependency vulnerability is about the package, not about the lock file that mentions
    /// it, and the SARIF location points at the lock file. Left that way, every one of Trivy's
    /// dependency findings would decorate a single <c>code:…deps.json</c> node, and none of
    /// them would meet OSV-Scanner's findings about the very same package on the very same
    /// node. Trivy states the package in the message body and nowhere else, so this reads it
    /// from there — and returning null when the shape changes simply falls back to the lock
    /// file rather than inventing a package.
    /// </remarks>
    private static string? PackageCoordinate(string message)
    {
        var match = PackageAndVersion().Match(message);
        return match.Success
            ? $"{match.Groups["name"].Value.Trim()}@{match.Groups["version"].Value.Trim()}"
            : null;
    }

    [GeneratedRegex(
        @"^Package:\s*(?<name>.+?)\s*$\s*^Installed Version:\s*(?<version>.+?)\s*$",
        RegexOptions.Multiline)]
    private static partial Regex PackageAndVersion();
}

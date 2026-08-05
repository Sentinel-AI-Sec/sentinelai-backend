using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// Normalizes Trivy SARIF. Trivy straddles two layers in one file: a vulnerability result
/// carries a CVE and belongs to the dependency layer, while a misconfiguration result does not
/// and belongs to infrastructure.
/// </summary>
public sealed class TrivySarifExtractor : IFindingExtractor
{
    public string SourceTool => ScannerNames.Trivy;

    public IEnumerable<Finding> Extract(Stream fileContent, Guid tenantId, Guid scanJobId)
    {
        var findings = new List<Finding>();
        foreach (var result in SarifReader.Read(fileContent))
        {
            // A CVE means this is a dependency vulnerability; anything else is a config check.
            var layer = result.CveId is not null ? Layer.Dep : Layer.Infra;
            findings.Add(SarifFindings.From(result, SourceTool, layer, tenantId, scanJobId));
        }

        return findings;
    }
}

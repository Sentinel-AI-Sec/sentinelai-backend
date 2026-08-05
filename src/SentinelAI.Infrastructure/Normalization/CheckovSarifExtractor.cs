using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// Normalizes Checkov SARIF. Checkov reports infrastructure misconfigurations (Terraform, the
/// Dockerfile), so every finding is tagged <see cref="Layer.Infra"/>.
/// </summary>
/// <remarks>
/// The runner emits Checkov twice — <c>checkov_infra.sarif</c> and <c>checkov_docker.sarif</c> —
/// and this same extractor handles both; the pipeline routes each file to it by name.
/// </remarks>
public sealed class CheckovSarifExtractor : IFindingExtractor
{
    public string SourceTool => ScannerNames.Checkov;

    public IEnumerable<Finding> Extract(Stream fileContent, Guid tenantId, Guid scanJobId)
    {
        var findings = new List<Finding>();
        foreach (var result in SarifReader.Read(fileContent))
            findings.Add(SarifFindings.From(result, SourceTool, Layer.Infra, tenantId, scanJobId));

        return findings;
    }
}

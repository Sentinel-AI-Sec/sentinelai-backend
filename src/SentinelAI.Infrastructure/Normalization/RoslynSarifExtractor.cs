using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// Normalizes Security Code Scan (Roslyn) SARIF. Roslyn runs inside the .NET build and reports
/// on the code layer — the CWE-502-class problems the other tools cannot see.
/// </summary>
public sealed class RoslynSarifExtractor : IFindingExtractor
{
    public string SourceTool => ScannerNames.Roslyn;

    public IEnumerable<Finding> Extract(Stream fileContent, Guid tenantId, Guid scanJobId)
    {
        var findings = new List<Finding>();
        foreach (var result in SarifReader.Read(fileContent))
            findings.Add(SarifFindings.From(result, SourceTool, Layer.Code, tenantId, scanJobId));

        return findings;
    }
}

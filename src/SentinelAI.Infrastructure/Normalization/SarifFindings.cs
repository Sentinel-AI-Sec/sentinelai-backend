using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// Builds a canonical <see cref="Finding"/> from a flattened SARIF result. Shared by the three
/// SARIF-based extractors so the field-by-field mapping — and the rule that
/// <see cref="Finding.NodeRef"/> is left empty for the graph stage — is written once.
/// </summary>
internal static class SarifFindings
{
    public static Finding From(SarifResult result, string sourceTool, Layer layer, Guid tenantId, Guid scanJobId)
        => new()
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            ScanJobId = scanJobId,
            SourceTool = sourceTool,
            Layer = layer,
            Severity = SeverityScale.FromSarif(result.Level, result.SecuritySeverity),
            CweId = result.CweId,
            CveId = result.CveId,
            // Kept for the rule-mapping step (SEC-15): when CweId came back null above, the
            // rule id is the only key that can still resolve one. Not persisted.
            CheckId = result.RuleId,
            // Left empty on purpose: the node key is built by NodeId at the graph stage, never
            // by concatenation here (SEC-03).
            NodeRef = string.Empty,
            Message = result.Message,
            Redacted = false,
        };
}

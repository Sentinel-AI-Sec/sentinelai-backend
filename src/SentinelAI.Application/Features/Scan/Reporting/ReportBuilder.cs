using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Reporting;

/// <summary>
/// The report stage of the walking skeleton (SEC-45): wraps the debate's adjudicated output in
/// a persistable <see cref="Report"/>, with one <see cref="Citation"/> per knowledge chunk the
/// retrieval stage returned.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Framing"/> is a constant, not a parameter. AID-01 §7 makes the draft-audit framing
/// non-negotiable — the output is prioritized material for human review, never a verified
/// verdict — and a caller able to pass "verdict" here is the one line of code that would undo
/// that. The disclaimer travels with the summary for the same reason.
/// </para>
/// <para>
/// Citations are built only from chunks that were actually retrieved. A report that cites
/// knowledge nobody fetched is worse than one that cites nothing: it reads as sourced.
/// </para>
/// </remarks>
public sealed class ReportBuilder
{
    /// <summary>AID-01 §7. The only framing this system emits.</summary>
    public const string DraftAudit = "draft_audit";

    public Report Build(
        DraftAudit audit,
        IReadOnlyList<string> knowledge,
        Guid tenantId,
        Guid scanJobId,
        string collection,
        DateTime createdAtUtc)
    {
        ArgumentNullException.ThrowIfNull(audit);

        var report = new Report
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            ScanJobId = scanJobId,
            Framing = DraftAudit,
            // The disclaimer is part of the text, not a field a renderer may forget to show.
            Summary = $"{audit.Summary}{Environment.NewLine}{Environment.NewLine}{audit.Disclaimer}",
            Retained = false,
            CreatedAt = createdAtUtc,
        };

        Bill(report, audit.Cost);

        foreach (var chunk in knowledge)
        {
            report.Citations.Add(new Citation
            {
                Id = Guid.CreateVersion7(),
                TenantId = tenantId,
                ReportId = report.Id,
                KnowledgeId = KnowledgeIdOf(chunk),
                Source = SourceOf(chunk),
                Collection = collection,
            });
        }

        return report;
    }

    /// <summary>
    /// Copies the debate's per-tier spend onto the report, so SEC-31's "cost per scan" is a
    /// stored fact rather than something only the process that ran the debate ever saw.
    /// </summary>
    /// <remarks>
    /// A tier the debate never used leaves its columns at zero, which is correct: no call, no
    /// tokens, no cost. What the zeros must not be read as is a priced result — that is what
    /// <see cref="Report.CostRated"/> is for.
    /// </remarks>
    private static void Bill(Report report, AuditCost cost)
    {
        var high = cost.UsageFor(ModelTier.High);
        var cheap = cost.UsageFor(ModelTier.Cheap);

        report.CostCurrency = cost.Currency;
        report.HighTierInputTokens = high.InputTokens;
        report.HighTierOutputTokens = high.OutputTokens;
        report.HighTierCost = cost.CostFor(ModelTier.High);
        report.CheapTierInputTokens = cheap.InputTokens;
        report.CheapTierOutputTokens = cheap.OutputTokens;
        report.CheapTierCost = cost.CostFor(ModelTier.Cheap);
        report.ModelCalls = cost.TotalCalls;
        report.CostRated = cost.FullyRated;
    }

    /// <summary>
    /// The linking key the chunk was retrieved for, which the seed retriever writes as a
    /// leading <c>[CWE-502]</c> tag. Falls back to the whole chunk so a citation is never
    /// created with an empty id.
    /// </summary>
    private static string KnowledgeIdOf(string chunk)
    {
        if (chunk.StartsWith('[') && chunk.IndexOf(']') is var close and > 1)
            return chunk[1..close];

        return chunk.Length <= 64 ? chunk : chunk[..64];
    }

    /// <summary>
    /// Which corpus the chunk came from, read from the text it quotes. Coarse on purpose: the
    /// real retriever will return a source field and this guess goes away with it.
    /// </summary>
    private static string SourceOf(string chunk) =>
        chunk.Contains("ATT&CK", StringComparison.OrdinalIgnoreCase) ? "ATT&CK"
        : chunk.Contains("CAPEC", StringComparison.OrdinalIgnoreCase) ? "CAPEC"
        : chunk.Contains("OWASP", StringComparison.OrdinalIgnoreCase) ? "OWASP"
        : "unknown";
}

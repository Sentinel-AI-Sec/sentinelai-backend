using SentinelAI.Application.Debate;
using SentinelAI.Application.Features.Scan.Reporting;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Tests.Reporting;

/// <summary>
/// SEC-31 step 4: the cost figure has to survive past the process that measured it, so the
/// report the pipeline persists carries the per-tier spend.
/// </summary>
public class ReportCostTests
{
    private static DebateTurn Turn(AgentRole role, ModelTier tier, long input, long output) => new()
    {
        Role = role,
        Round = 1,
        Content = "…",
        Tier = tier,
        Usage = new TokenUsage(input, output)
    };

    private static DraftAudit AuditCosting(AuditCost cost) => new()
    {
        Summary = "ADJUDICATE: chain survives.",
        Transcript = [],
        Rounds = 1,
        TerminatedByTurnCap = false,
        Converged = true,
        Cost = cost
    };

    private static Report Build(DraftAudit audit) =>
        new ReportBuilder().Build(
            audit, [], Guid.NewGuid(), Guid.NewGuid(), "offense", DateTime.UtcNow);

    [Fact]
    public void The_report_records_tokens_and_money_for_each_tier()
    {
        var cost = CostAccounting.Measure(
        [
            Turn(AgentRole.Orchestrator, ModelTier.Cheap, 1_000_000, 0),
            Turn(AgentRole.Red, ModelTier.High, 1_000_000, 0),
            Turn(AgentRole.Blue, ModelTier.High, 0, 1_000_000),
        ], ModelPricing.For(high: new TierRate(2m, 8m), cheap: new TierRate(1m, 4m)));

        var report = Build(AuditCosting(cost));

        Assert.Equal(1_000_000, report.HighTierInputTokens);
        Assert.Equal(1_000_000, report.HighTierOutputTokens);
        Assert.Equal(1_000_000, report.CheapTierInputTokens);
        Assert.Equal(0, report.CheapTierOutputTokens);

        Assert.Equal(10m, report.HighTierCost);   // 1M in at $2 + 1M out at $8
        Assert.Equal(1m, report.CheapTierCost);   // 1M in at $1
        Assert.Equal(11m, report.TotalCost);

        Assert.Equal(3, report.ModelCalls);
        Assert.Equal("USD", report.CostCurrency);
        Assert.True(report.CostRated);
    }

    /// <summary>
    /// Once the numbers are in a database nobody can see which provider produced them, so the
    /// "no rate was configured" case has to be stored, not inferred from a zero.
    /// </summary>
    [Fact]
    public void An_unpriced_debate_is_stored_as_unrated_rather_than_free()
    {
        var cost = CostAccounting.Measure(
            [Turn(AgentRole.Red, ModelTier.High, 4_000, 900)], ModelPricing.Unpriced);

        var report = Build(AuditCosting(cost));

        Assert.Equal(4_000, report.HighTierInputTokens);
        Assert.Equal(0m, report.TotalCost);
        Assert.False(report.CostRated);
    }

    [Fact]
    public void An_audit_with_nothing_measured_leaves_the_columns_at_zero()
    {
        var report = Build(AuditCosting(AuditCost.None));

        Assert.Equal(0, report.ModelCalls);
        Assert.Equal(0m, report.TotalCost);
        Assert.Equal(0, report.HighTierInputTokens);
        Assert.Equal(0, report.CheapTierOutputTokens);
    }

    /// <summary>Cost is added alongside the framing, not instead of it.</summary>
    [Fact]
    public void The_draft_audit_framing_still_holds()
    {
        var report = Build(AuditCosting(AuditCost.None));

        Assert.Equal(ReportBuilder.DraftAudit, report.Framing);
        Assert.Contains("not a verified verdict", report.Summary);
    }
}

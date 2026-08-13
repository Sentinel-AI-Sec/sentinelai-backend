using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Tests.Debate;

/// <summary>
/// SEC-31 step 3: <em>"Record tokens and cost per scan, broken down by tier."</em>
/// </summary>
/// <remarks>
/// These are the arithmetic and the honesty rules, away from any provider. The end-to-end
/// proof that a real debate produces these numbers lives in
/// <c>SentinelAI.Integration.Tests.Agents.CostTrackingTests</c>.
/// </remarks>
public class CostAccountingTests
{
    private static DebateTurn Turn(AgentRole role, ModelTier tier, long input, long output) => new()
    {
        Role = role,
        Round = 1,
        Content = "…",
        Tier = tier,
        Usage = new TokenUsage(input, output)
    };

    /// <summary>Round numbers: $1 per million in, $10 per million out on High; $0.10/$1 on Cheap.</summary>
    private static ModelPricing Pricing() =>
        ModelPricing.For(high: new TierRate(1m, 10m), cheap: new TierRate(0.10m, 1m));

    [Fact]
    public void Spend_is_grouped_by_the_tier_that_served_each_turn()
    {
        var cost = CostAccounting.Measure(
        [
            Turn(AgentRole.Orchestrator, ModelTier.Cheap, 100, 50),
            Turn(AgentRole.Red, ModelTier.High, 1_000, 500),
            Turn(AgentRole.Blue, ModelTier.High, 2_000, 400),
        ], Pricing());

        Assert.Equal(new TokenUsage(3_000, 900), cost.UsageFor(ModelTier.High));
        Assert.Equal(new TokenUsage(100, 50), cost.UsageFor(ModelTier.Cheap));
        Assert.Equal(2, cost.For(ModelTier.High)!.Calls);
        Assert.Equal(1, cost.For(ModelTier.Cheap)!.Calls);
        Assert.Equal(3, cost.TotalCalls);
    }

    [Fact]
    public void Input_and_output_tokens_are_priced_at_their_own_rates()
    {
        var cost = CostAccounting.Measure([Turn(AgentRole.Red, ModelTier.High, 1_000_000, 100_000)], Pricing());

        // 1M input at $1 + 100k output at $10/M = 1.00 + 1.00.
        Assert.Equal(2.00m, cost.CostFor(ModelTier.High));
        Assert.Equal(2.00m, cost.Total);
    }

    /// <summary>
    /// The whole point of two tiers: the same tokens cost an order of magnitude less on the
    /// cheap one. If this ever came out equal, routing would be buying nothing.
    /// </summary>
    [Fact]
    public void The_cheap_tier_is_cheaper_for_identical_usage()
    {
        var expensive = CostAccounting.Measure([Turn(AgentRole.Red, ModelTier.High, 10_000, 5_000)], Pricing());
        var cheap = CostAccounting.Measure([Turn(AgentRole.Red, ModelTier.Cheap, 10_000, 5_000)], Pricing());

        Assert.True(cheap.Total < expensive.Total);
    }

    [Fact]
    public void A_tier_that_served_no_turn_is_absent_rather_than_zero()
    {
        var cost = CostAccounting.Measure([Turn(AgentRole.Red, ModelTier.High, 10, 10)], Pricing());

        Assert.Null(cost.For(ModelTier.Cheap));
        Assert.Equal(TokenUsage.None, cost.UsageFor(ModelTier.Cheap));
        Assert.Single(cost.ByTier);
    }

    /// <summary>
    /// A missing rate must not read as a free debate. The tokens are still true, so they are
    /// kept; the money is not claimed, and <c>Rated</c> says which is which.
    /// </summary>
    [Fact]
    public void Tokens_on_an_unpriced_tier_are_recorded_but_not_priced()
    {
        var cost = CostAccounting.Measure(
            [Turn(AgentRole.Red, ModelTier.High, 5_000, 1_000)], ModelPricing.Unpriced);

        Assert.Equal(new TokenUsage(5_000, 1_000), cost.UsageFor(ModelTier.High));
        Assert.Equal(0m, cost.Total);
        Assert.False(cost.For(ModelTier.High)!.Rated);
        Assert.False(cost.FullyRated);

        // Measured stays true: a provider did report usage. "Unpriced" and "unused" are
        // different claims and the audit has to be able to make each of them.
        Assert.True(cost.Measured);
    }

    [Fact]
    public void One_unpriced_tier_makes_the_whole_audit_unrated()
    {
        var partial = ModelPricing.Unpriced;
        partial.Tiers[ModelTier.Cheap] = new TierRate(0.10m, 1m);

        var cost = CostAccounting.Measure(
        [
            Turn(AgentRole.Red, ModelTier.High, 1_000, 1_000),
            Turn(AgentRole.Orchestrator, ModelTier.Cheap, 1_000, 1_000),
        ], partial);

        Assert.True(cost.For(ModelTier.Cheap)!.Rated);
        Assert.False(cost.For(ModelTier.High)!.Rated);
        Assert.False(cost.FullyRated);
    }

    /// <summary>
    /// The offline provider really is free, so zero money with a real rate behind it must be
    /// distinguishable from zero money because nobody set a rate.
    /// </summary>
    [Fact]
    public void A_genuinely_free_provider_reports_zero_and_stays_rated()
    {
        var cost = CostAccounting.Measure(
            [Turn(AgentRole.Red, ModelTier.High, 400, 200)], ModelPricing.Free());

        Assert.Equal(0m, cost.Total);
        Assert.True(cost.FullyRated);
        Assert.True(cost.Measured);
    }

    [Fact]
    public void A_provider_that_reported_no_usage_is_recorded_as_unmeasured()
    {
        var cost = CostAccounting.Measure([Turn(AgentRole.Red, ModelTier.High, 0, 0)], Pricing());

        Assert.False(cost.Measured);
        Assert.Equal(1, cost.TotalCalls);
    }

    [Fact]
    public void No_turns_means_nothing_measured_rather_than_zero_spend()
    {
        Assert.Same(AuditCost.None, CostAccounting.Measure([], Pricing()));
        Assert.Same(AuditCost.None, CostAccounting.Measure(null, Pricing()));
        Assert.False(AuditCost.None.Measured);
        Assert.Empty(AuditCost.None.ByTier);
    }

    /// <summary>
    /// Two runs of the same scan must produce a diffable breakdown, so the order is the
    /// enum's and not the order the debate happened to call the tiers in.
    /// </summary>
    [Fact]
    public void The_breakdown_is_ordered_by_tier_not_by_call_order()
    {
        var cost = CostAccounting.Measure(
        [
            Turn(AgentRole.Orchestrator, ModelTier.Cheap, 10, 10),
            Turn(AgentRole.Red, ModelTier.High, 10, 10),
        ], Pricing());

        Assert.Equal([ModelTier.High, ModelTier.Cheap], cost.ByTier.Select(t => t.Tier));
    }

    [Fact]
    public void Currency_comes_from_the_price_list()
    {
        var cost = CostAccounting.Measure(
            [Turn(AgentRole.Red, ModelTier.High, 10, 10)],
            ModelPricing.For(new TierRate(1m, 1m), new TierRate(1m, 1m), currency: "EUR"));

        Assert.Equal("EUR", cost.Currency);
    }
}

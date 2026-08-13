using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Debate;

/// <summary>
/// Turns a debate's turns into the cost figure SEC-31 puts on the audit: tokens and money,
/// grouped by the model tier that served them.
/// </summary>
/// <remarks>
/// <para>
/// It folds over the turns rather than over a running counter kept by the debate. The turns
/// are what the checkpoint stores, so a run resumed after an interruption still accounts for
/// what was spent before it — an in-memory accumulator would restart at zero and report a
/// long debate as a cheap one.
/// </para>
/// <para>
/// It is deliberately total: no configuration, no provider, no clock, and no failure mode.
/// Cost tracking must never be the reason an audit does not come out.
/// </para>
/// </remarks>
public static class CostAccounting
{
    /// <summary>
    /// Groups <paramref name="turns"/> by tier and prices each group.
    /// </summary>
    /// <param name="turns">Every model-backed turn of the debate, seed included.</param>
    /// <param name="pricing">Rates to apply. Null or empty records tokens without money.</param>
    public static AuditCost Measure(IEnumerable<DebateTurn>? turns, ModelPricing? pricing)
    {
        if (turns is null) return AuditCost.None;

        var byTier = turns
            .GroupBy(turn => turn.Tier)
            // Ordered by the enum so High always precedes Cheap, whatever order the debate
            // happened to call them in. A breakdown that reorders itself between two runs of
            // the same scan is not a breakdown anyone can diff.
            .OrderBy(group => group.Key)
            .Select(group => Price(group.Key, [.. group], pricing))
            .ToList();

        return byTier.Count == 0
            ? AuditCost.None
            : new AuditCost { Currency = pricing?.Currency ?? "USD", ByTier = byTier };
    }

    private static TierSpend Price(ModelTier tier, IReadOnlyList<DebateTurn> turns, ModelPricing? pricing)
    {
        var usage = turns.Aggregate(TokenUsage.None, (running, turn) => running + turn.Usage);
        var rate = pricing?.RateFor(tier);

        return new TierSpend(
            Tier: tier,
            Calls: turns.Count,
            Usage: usage,
            // An unrated tier reports zero money and says so through Rated, rather than
            // guessing at a price or throwing away the tokens it does know about.
            Cost: rate?.CostOf(usage) ?? 0m,
            Rated: rate is not null);
    }
}

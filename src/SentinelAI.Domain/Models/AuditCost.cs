using System.Text.Json.Serialization;

namespace SentinelAI.Domain.Models;

/// <summary>
/// What one model tier was used for, and what it cost, across a single audit.
/// </summary>
/// <param name="Tier">The tier these turns were routed to.</param>
/// <param name="Calls">How many model calls the tier served.</param>
/// <param name="Usage">Tokens billed by the tier.</param>
/// <param name="Cost">Money, in <see cref="AuditCost.Currency"/>. Zero when <paramref name="Rated"/> is false.</param>
/// <param name="Rated">
/// False when tokens were spent on this tier but no price was configured for it. The tokens
/// are still true; the money is not, and this flag is what stops a missing rate reading as a
/// free debate.
/// </param>
public sealed record TierSpend(
    ModelTier Tier,
    int Calls,
    TokenUsage Usage,
    decimal Cost,
    bool Rated);

/// <summary>
/// Cost of one audit, broken down by model tier — the SEC-31 acceptance criterion
/// ("given a completed audit, when measured, then cost per audit by model tier is recorded").
/// </summary>
/// <remarks>
/// <para>
/// Tokens and money are reported side by side because only one of them is ever certain.
/// Tokens come from the provider's own response. Money is tokens multiplied by a rate we
/// configured, which can be stale, missing, or written for a different provider than the one
/// actually serving the debate. <see cref="FullyRated"/> says which case this is.
/// </para>
/// <para>
/// A tier with no turns is omitted rather than reported as zero, so "the cheap tier was never
/// used" and "the cheap tier was used and cost nothing" stay distinguishable.
/// </para>
/// </remarks>
public sealed record AuditCost
{
    /// <summary>No model call was measured. The starting value, not an assertion of zero spend.</summary>
    public static readonly AuditCost None = new() { ByTier = [] };

    /// <summary>ISO currency code the rates were quoted in.</summary>
    public string Currency { get; init; } = "USD";

    /// <summary>One entry per tier that actually served a turn, in tier order.</summary>
    public required IReadOnlyList<TierSpend> ByTier { get; init; }

    /// <summary>Total money across every tier.</summary>
    [JsonIgnore]
    public decimal Total => ByTier.Sum(t => t.Cost);

    /// <summary>Total tokens across every tier.</summary>
    [JsonIgnore]
    public TokenUsage TotalUsage =>
        ByTier.Aggregate(TokenUsage.None, (running, tier) => running + tier.Usage);

    /// <summary>Total model calls across every tier.</summary>
    [JsonIgnore]
    public int TotalCalls => ByTier.Sum(t => t.Calls);

    /// <summary>
    /// True when every tier that spent tokens had a price to spend them at, so
    /// <see cref="Total"/> is a real figure rather than an under-count.
    /// </summary>
    [JsonIgnore]
    public bool FullyRated => ByTier.All(t => t.Rated || t.Usage.IsEmpty);

    /// <summary>
    /// True when at least one provider reported token usage. False for a debate that never
    /// reached a provider — which is a different thing from one that was free.
    /// </summary>
    [JsonIgnore]
    public bool Measured => ByTier.Any(t => !t.Usage.IsEmpty);

    /// <summary>This tier's spend, or null when the tier served no turn.</summary>
    public TierSpend? For(ModelTier tier) => ByTier.FirstOrDefault(t => t.Tier == tier);

    /// <summary>Tokens billed by one tier. Zero when the tier served no turn.</summary>
    public TokenUsage UsageFor(ModelTier tier) => For(tier)?.Usage ?? TokenUsage.None;

    /// <summary>Money spent on one tier. Zero when the tier served no turn.</summary>
    public decimal CostFor(ModelTier tier) => For(tier)?.Cost ?? 0m;
}

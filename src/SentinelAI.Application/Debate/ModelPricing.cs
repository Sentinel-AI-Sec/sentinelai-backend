using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Debate;

/// <summary>
/// What one tier charges, quoted the way every provider publishes it: money per million
/// tokens, priced separately for input and output.
/// </summary>
/// <param name="InputPerMillionTokens">Price of 1,000,000 prompt tokens.</param>
/// <param name="OutputPerMillionTokens">Price of 1,000,000 completion tokens.</param>
public sealed record TierRate(decimal InputPerMillionTokens, decimal OutputPerMillionTokens)
{
    private const decimal Million = 1_000_000m;

    /// <summary>A tier that genuinely costs nothing — the offline Scripted provider.</summary>
    public static readonly TierRate Free = new(0m, 0m);

    /// <summary>Parameterless ctor so the configuration binder can construct one.</summary>
    public TierRate() : this(0m, 0m) { }

    /// <summary>Money for this usage. No rounding — the caller decides how to display it.</summary>
    public decimal CostOf(TokenUsage usage) =>
        (usage.InputTokens * InputPerMillionTokens / Million)
        + (usage.OutputTokens * OutputPerMillionTokens / Million);
}

/// <summary>
/// Price list for the two model tiers, bound from <c>SentinelAI:Models:Pricing</c>.
/// </summary>
/// <remarks>
/// <para>
/// Prices belong to the provider, but this type does not know which provider it describes and
/// must not: <c>ProviderPricing</c> in Infrastructure picks the defaults for the configured
/// vendor and hands the result here, which is the same seam SEC-30 drew for models and keys.
/// The consequence to keep in mind is the one SEC-30's notes already flag — nothing compares
/// spend <em>across</em> providers, so switching provider without updating rates prices the
/// new one at the old one's numbers.
/// </para>
/// <para>
/// A tier with no rate is <em>unrated</em>, not free. <see cref="RateFor"/> returns null for
/// it and the audit records the tokens with <c>Rated = false</c>, because a provider whose
/// list price nobody entered must not read as a debate that cost nothing.
/// </para>
/// </remarks>
public sealed class ModelPricing
{
    public const string SectionName = "SentinelAI:Models:Pricing";

    /// <summary>An empty price list: tokens will be counted, money will not be claimed.</summary>
    public static ModelPricing Unpriced => new();

    /// <summary>ISO code the rates are quoted in. Informational — no conversion is done.</summary>
    public string Currency { get; set; } = "USD";

    /// <summary>Rate per tier. A missing entry means "no price configured".</summary>
    public IDictionary<ModelTier, TierRate> Tiers { get; } = new Dictionary<ModelTier, TierRate>();

    /// <summary>True when at least one tier has a price.</summary>
    public bool HasRates => Tiers.Count > 0;

    /// <summary>The tier's rate, or null when none was configured.</summary>
    public TierRate? RateFor(ModelTier tier) =>
        Tiers.TryGetValue(tier, out var rate) ? rate : null;

    /// <summary>Builds a price list covering both tiers at the given rates.</summary>
    public static ModelPricing For(TierRate high, TierRate cheap, string currency = "USD")
    {
        ArgumentNullException.ThrowIfNull(high);
        ArgumentNullException.ThrowIfNull(cheap);

        var pricing = new ModelPricing { Currency = currency };
        pricing.Tiers[ModelTier.High] = high;
        pricing.Tiers[ModelTier.Cheap] = cheap;
        return pricing;
    }

    /// <summary>Every tier priced at zero — correct only for a provider that really is free.</summary>
    public static ModelPricing Free(string currency = "USD") =>
        For(TierRate.Free, TierRate.Free, currency);
}

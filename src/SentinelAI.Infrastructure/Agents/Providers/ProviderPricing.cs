using System.Globalization;
using Microsoft.Extensions.Configuration;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Agents.Providers;

/// <summary>
/// Where SEC-31's money comes from: the per-tier token rates for the configured provider,
/// read from <c>SentinelAI:Models:Pricing</c> and falling back to published list prices.
/// </summary>
/// <remarks>
/// <para>
/// This is the only vendor-aware part of cost tracking, and it sits beside the other vendor
/// detail on purpose. Everything above it — <see cref="ModelPricing"/>, the audit's
/// breakdown, the executors that stamp a tier on their turn — names no provider.
/// </para>
/// <para>
/// The built-in numbers are list prices per million tokens at the time of writing, and they
/// are a convenience, not a source of truth: vendors reprice, and a deployment with negotiated
/// rates pays something else entirely. Anything in configuration wins over them, per tier.
/// </para>
/// <para>
/// Where no list price is known — NIM, whose pricing depends on how it is hosted — the tier is
/// left <em>unrated</em> rather than defaulted to zero. Tokens are still counted and the audit
/// reports <c>Rated = false</c>, which is the difference between "we do not know what this
/// cost" and "this was free". The same rule the embedder follows in AID-01 §5: no silent
/// fallback to a number that looks fine.
/// </para>
/// </remarks>
public static class ProviderPricing
{
    /// <summary>List prices in USD per million tokens, by provider and tier.</summary>
    /// <remarks>
    /// Azure entries are for the models the tier defaults name (gpt-4o, gpt-4o-mini) rather
    /// than for whatever deployment they were given — Azure prices the model behind the
    /// deployment, and a deployment named after a different model is priced wrong here.
    /// </remarks>
    private static readonly Dictionary<(ModelProvider Provider, ModelTier Tier), TierRate> ListPrices = new()
    {
        // Scripted is genuinely free: no request leaves the process.
        [(ModelProvider.Scripted, ModelTier.High)] = TierRate.Free,
        [(ModelProvider.Scripted, ModelTier.Cheap)] = TierRate.Free,

        // gpt-4o / gpt-4o-mini.
        [(ModelProvider.AzureOpenAI, ModelTier.High)] = new(2.50m, 10.00m),
        [(ModelProvider.AzureOpenAI, ModelTier.Cheap)] = new(0.15m, 0.60m),

        // claude-sonnet / claude-haiku.
        [(ModelProvider.Anthropic, ModelTier.High)] = new(3.00m, 15.00m),
        [(ModelProvider.Anthropic, ModelTier.Cheap)] = new(1.00m, 5.00m),

        // NIM is deliberately absent — see the remarks on this type.
    };

    /// <summary>Currency every built-in list price is quoted in.</summary>
    public const string DefaultCurrency = "USD";

    /// <summary>
    /// The price list to bill this provider's debates with: configuration first, list price
    /// second, unrated if neither supplies one.
    /// </summary>
    public static ModelPricing Load(IConfiguration configuration, ModelProvider provider)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var section = configuration.GetSection(ModelPricing.SectionName);
        var pricing = new ModelPricing
        {
            Currency = Blank(section["Currency"]) ?? DefaultCurrency
        };

        foreach (var tier in Enum.GetValues<ModelTier>())
        {
            // Read each tier by name rather than binding the enum-keyed dictionary, for the
            // reason ModelOptionsLoader gives: the binder swallows a misspelt key, and a rate
            // that silently fails to load is indistinguishable from one nobody entered.
            var configured = RateFrom(section.GetSection(tier.ToString()));
            var rate = configured ?? DefaultFor(provider, tier);

            if (rate is not null) pricing.Tiers[tier] = rate;
        }

        return pricing;
    }

    /// <summary>The built-in list price for a tier, or null if none is published.</summary>
    public static TierRate? DefaultFor(ModelProvider provider, ModelTier tier) =>
        ListPrices.TryGetValue((provider, tier), out var rate) ? rate : null;

    /// <summary>Every built-in rate for a provider, with no configuration involved.</summary>
    public static ModelPricing DefaultsFor(ModelProvider provider)
    {
        var pricing = new ModelPricing { Currency = DefaultCurrency };

        foreach (var tier in Enum.GetValues<ModelTier>())
            if (DefaultFor(provider, tier) is { } rate)
                pricing.Tiers[tier] = rate;

        return pricing;
    }

    /// <summary>
    /// One tier's configured rate. Both halves must be present and non-negative — a rate with
    /// only an input price would bill output at zero, which under-reports rather than fails.
    /// </summary>
    private static TierRate? RateFrom(IConfigurationSection section)
    {
        var input = Decimal(section["InputPerMillionTokens"]);
        var output = Decimal(section["OutputPerMillionTokens"]);

        return input is { } i && output is { } o && i >= 0m && o >= 0m ? new TierRate(i, o) : null;
    }

    private static decimal? Decimal(string? value) =>
        decimal.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}

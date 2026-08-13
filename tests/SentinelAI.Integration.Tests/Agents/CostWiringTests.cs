using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// The container half of SEC-31: the price list has to reach the debate engine.
/// </summary>
/// <remarks>
/// Worth its own test because the failure is invisible at compile time and only shows up in a
/// running host. <c>DebateEngine</c> takes its pricing as an optional constructor parameter, so
/// forgetting to register <c>ModelPricing</c> would not break the build — it would either throw
/// while the host boots or, worse, quietly construct an engine that counts tokens and prices
/// none of them.
/// </remarks>
public class CostWiringTests
{
    private static ServiceProvider Build(Dictionary<string, string?> settings)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

        return new ServiceCollection()
            .AddDebateServices(configuration)
            .BuildServiceProvider();
    }

    [Fact]
    public void The_debate_engine_resolves_with_its_price_list()
    {
        using var services = Build(new() { ["SentinelAI:Models:Provider"] = "Scripted" });

        Assert.NotNull(services.GetRequiredService<IDebateEngine>());
        Assert.NotNull(services.GetRequiredService<ModelPricing>());
    }

    /// <summary>Rates follow the configured provider, with no pricing section present.</summary>
    [Fact]
    public void The_registered_rates_are_the_configured_providers()
    {
        using var services = Build(new()
        {
            ["SentinelAI:Models:Provider"] = "Anthropic",
            ["SentinelAI:Models:ApiKey"] = "test-key-never-leaves-the-process",
        });

        var pricing = services.GetRequiredService<ModelPricing>();

        Assert.Equal(
            ProviderPricing.DefaultFor(ModelProvider.Anthropic, ModelTier.High),
            pricing.RateFor(ModelTier.High));
    }

    [Fact]
    public void Configured_rates_reach_the_container()
    {
        using var services = Build(new()
        {
            ["SentinelAI:Models:Provider"] = "Scripted",
            ["SentinelAI:Models:Pricing:Currency"] = "EUR",
            ["SentinelAI:Models:Pricing:High:InputPerMillionTokens"] = "7",
            ["SentinelAI:Models:Pricing:High:OutputPerMillionTokens"] = "70",
        });

        var pricing = services.GetRequiredService<ModelPricing>();

        Assert.Equal("EUR", pricing.Currency);
        Assert.Equal(new TierRate(7m, 70m), pricing.RateFor(ModelTier.High));

        // The tier nobody overrode keeps the provider's own rate — here, a genuine zero.
        Assert.Equal(TierRate.Free, pricing.RateFor(ModelTier.Cheap));
    }
}

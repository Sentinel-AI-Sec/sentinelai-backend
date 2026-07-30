using Microsoft.Extensions.AI;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// AID-01 section 2: "the model sits behind the connector abstraction, so switching
/// provider is a config change, proven by an integration test."
/// </summary>
/// <remarks>
/// These construct clients but never call them, so nothing here touches the network.
/// </remarks>
public class ProviderSwitchTests
{
    [Fact]
    public void Default_provider_is_the_offline_scripted_client()
    {
        var client = new ChatClientFactory(new ModelProviderOptions()).Create(AgentRole.Red, ModelTier.High);
        Assert.IsType<ScriptedChatClient>(client);
    }

    [Theory]
    [InlineData(ModelProvider.Nim)]
    [InlineData(ModelProvider.Anthropic)]
    public void Switching_provider_is_config_only(ModelProvider provider)
    {
        var options = new ModelProviderOptions { Provider = provider, ApiKey = "test-key-not-used" };

        var client = new ChatClientFactory(options).Create(AgentRole.Red, ModelTier.High);

        // A real OpenAI-wire client, not the stub - built from config alone.
        Assert.IsAssignableFrom<IChatClient>(client);
        Assert.IsNotType<ScriptedChatClient>(client);
    }

    [Theory]
    [InlineData(ModelProvider.Nim)]
    [InlineData(ModelProvider.Anthropic)]
    [InlineData(ModelProvider.AzureOpenAI)]
    public void A_live_provider_without_a_key_fails_loud(ModelProvider provider)
    {
        var factory = new ChatClientFactory(new ModelProviderOptions { Provider = provider });

        // Never silently degrade to an unauthenticated or stubbed call.
        var ex = Assert.Throws<InvalidOperationException>(() => factory.Create(AgentRole.Red, ModelTier.High));
        Assert.Contains("API key", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Azure_requires_an_explicit_endpoint()
    {
        var factory = new ChatClientFactory(new ModelProviderOptions
        {
            Provider = ModelProvider.AzureOpenAI,
            ApiKey = "test-key-not-used"
        });

        var ex = Assert.Throws<InvalidOperationException>(() => factory.Create(AgentRole.Red, ModelTier.High));
        Assert.Contains("endpoint", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Each_provider_carries_its_own_tier_defaults()
    {
        var nim = new ModelProviderOptions { Provider = ModelProvider.Nim };
        var claude = new ModelProviderOptions { Provider = ModelProvider.Anthropic };

        Assert.NotEqual(nim.ModelFor(ModelTier.High), nim.ModelFor(ModelTier.Cheap));
        Assert.Contains("llama", nim.ModelFor(ModelTier.High), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("sonnet", claude.ModelFor(ModelTier.High), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("haiku", claude.ModelFor(ModelTier.Cheap), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void An_explicit_model_id_overrides_the_tier_default()
    {
        var options = new ModelProviderOptions
        {
            Provider = ModelProvider.Nim,
            HighTierModel = "nvidia/llama-3.1-nemotron-70b-instruct"
        };

        Assert.Equal("nvidia/llama-3.1-nemotron-70b-instruct", options.ModelFor(ModelTier.High));
    }

    // Regression: the scripted client used to infer the role by sniffing the system
    // message, which silently matched nothing because ChatClientAgent passes instructions
    // via ChatOptions.Instructions instead. Every agent then returned the same fallback
    // string. The unit tests missed it - only running the demo exposed it.
    [Theory]
    [InlineData(AgentRole.Red, "ASSERT")]
    [InlineData(AgentRole.Blue, "VALIDATE")]
    [InlineData(AgentRole.Reporter, "ADJUDICATE")]
    public async Task The_scripted_client_answers_in_character_for_each_role(AgentRole role, string expected)
    {
        var client = new ChatClientFactory(new ModelProviderOptions()).Create(role, ModelTier.High);

        var response = await client.GetResponseAsync([new ChatMessage(ChatRole.User, "go")]);

        Assert.StartsWith(expected, response.Text);
    }

    [Fact]
    public void Every_debate_role_has_a_canned_turn()
    {
        foreach (var role in Enum.GetValues<AgentRole>())
            Assert.False(string.IsNullOrWhiteSpace(ScriptedChatClient.CannedTurnFor(role)));
    }
}


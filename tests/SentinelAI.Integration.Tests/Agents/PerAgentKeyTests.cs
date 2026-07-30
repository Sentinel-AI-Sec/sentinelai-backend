using Microsoft.Extensions.Configuration;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// Each agent carries its own credential, so a per-key rate limit or a leaked key is
/// scoped to one role rather than the whole debate.
/// </summary>
public class PerAgentKeyTests
{
    private static ModelProviderOptions Nim(Action<ModelProviderOptions> configure)
    {
        var options = new ModelProviderOptions { Provider = ModelProvider.Nim };
        configure(options);
        return options;
    }

    [Fact]
    public void Each_agent_resolves_its_own_key()
    {
        var options = Nim(o =>
        {
            o.Agents[AgentRole.Red] = new AgentModelOptions { ApiKey = "red-key" };
            o.Agents[AgentRole.Blue] = new AgentModelOptions { ApiKey = "blue-key" };
            o.Agents[AgentRole.Reporter] = new AgentModelOptions { ApiKey = "reporter-key" };
        });

        Assert.Equal("red-key", options.ApiKeyFor(AgentRole.Red));
        Assert.Equal("blue-key", options.ApiKeyFor(AgentRole.Blue));
        Assert.Equal("reporter-key", options.ApiKeyFor(AgentRole.Reporter));
    }

    [Fact]
    public void An_agent_without_its_own_key_falls_back_to_the_shared_one()
    {
        var options = Nim(o =>
        {
            o.ApiKey = "shared-key";
            o.Agents[AgentRole.Red] = new AgentModelOptions { ApiKey = "red-key" };
        });

        Assert.Equal("red-key", options.ApiKeyFor(AgentRole.Red));
        Assert.Equal("shared-key", options.ApiKeyFor(AgentRole.Blue));
    }

    // An unfilled dev.json placeholder must not be sent as a credential.
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void A_blank_key_counts_as_absent(string blank)
    {
        var options = Nim(o =>
        {
            o.ApiKey = "shared-key";
            o.Agents[AgentRole.Red] = new AgentModelOptions { ApiKey = blank };
        });

        Assert.Equal("shared-key", options.ApiKeyFor(AgentRole.Red));
    }

    [Fact]
    public void A_missing_key_names_the_agent_that_lacks_it()
    {
        var options = Nim(o => o.Agents[AgentRole.Red] = new AgentModelOptions { ApiKey = "red-key" });

        var ex = Assert.Throws<InvalidOperationException>(
            () => new ChatClientFactory(options).Create(AgentRole.Blue, ModelTier.High));

        Assert.Contains("Blue", ex.Message);
        Assert.Contains("API key", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Missing_keys_are_reported_for_every_agent_at_once()
    {
        var options = Nim(o => o.Agents[AgentRole.Red] = new AgentModelOptions { ApiKey = "red-key" });

        var missing = options.AgentsMissingKeys(DebateWorkflow.ModelBackedRoles);

        // Red is satisfied; the other three are named together so one run reports all.
        Assert.Equal([AgentRole.Orchestrator, AgentRole.Blue, AgentRole.Reporter], missing);
    }

    [Fact]
    public void The_orchestrator_is_required_to_have_a_key()
    {
        // The Orchestrator now calls the model to analyse the resource graph and produce
        // a strategic briefing, so it needs a credential like the other agents.
        Assert.Contains(AgentRole.Orchestrator, DebateWorkflow.ModelBackedRoles);
    }

    [Fact]
    public void An_agent_can_override_the_model_as_well_as_the_key()
    {
        var options = Nim(o =>
        {
            o.HighTierModel = "meta/llama-3.3-70b-instruct";
            o.Agents[AgentRole.Reporter] = new AgentModelOptions { Model = "z-ai/glm-5.2" };
        });

        Assert.Equal("meta/llama-3.3-70b-instruct", options.ModelFor(AgentRole.Red, ModelTier.High));
        Assert.Equal("z-ai/glm-5.2", options.ModelFor(AgentRole.Reporter, ModelTier.High));
    }

    [Fact]
    public void Four_keys_are_read_from_configuration()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SentinelAI:Models:Provider"] = "Nim",
                ["SentinelAI:Models:Agents:Orchestrator:ApiKey"] = "key-orchestrator",
                ["SentinelAI:Models:Agents:Red:ApiKey"] = "key-red",
                ["SentinelAI:Models:Agents:Blue:ApiKey"] = "key-blue",
                ["SentinelAI:Models:Agents:Reporter:ApiKey"] = "key-reporter",
                ["SentinelAI:Models:Agents:Reporter:Model"] = "z-ai/glm-5.2"
            })
            .Build();

        var options = ModelOptionsLoader.Load(configuration);

        Assert.Equal(ModelProvider.Nim, options.Provider);
        Assert.Equal(4, options.Agents.Count);
        foreach (var role in Enum.GetValues<AgentRole>())
            Assert.Equal($"key-{role.ToString().ToLowerInvariant()}", options.ApiKeyFor(role));

        Assert.Equal("z-ai/glm-5.2", options.ModelFor(AgentRole.Reporter, ModelTier.High));
        Assert.Empty(options.AgentsMissingKeys(DebateWorkflow.ModelBackedRoles));
    }

    [Fact]
    public void An_environment_variable_overrides_the_configured_key()
    {
        var variable = ModelOptionsLoader.KeyVariableFor(AgentRole.Blue);
        Assert.Equal("SENTINELAI_BLUE_API_KEY", variable);

        var options = Nim(o => o.Agents[AgentRole.Blue] = new AgentModelOptions { ApiKey = "from-file" });

        try
        {
            Environment.SetEnvironmentVariable(variable, "from-environment");
            ModelOptionsLoader.ApplyEnvironmentOverrides(options);

            // CI supplies secrets as environment variables, so they must win over a file.
            Assert.Equal("from-environment", options.ApiKeyFor(AgentRole.Blue));
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }
}

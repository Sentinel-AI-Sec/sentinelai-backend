using Microsoft.Extensions.Configuration;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Executors;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// SEC-30's acceptance criterion: <em>"Config change → provider switches; debate runs
/// unchanged (integration test asserts)."</em>
/// </summary>
/// <remarks>
/// <para>
/// The distinguishing feature of these tests is that nothing in them names a provider in code.
/// Each one starts from a configuration dictionary — the same thing <c>appsettings.json</c>
/// produces — and everything downstream is identical: same loader, same factory, same
/// workflow, same runner, same assertions. The only difference between a Scripted run and an
/// Azure run is a string in a dictionary. That is what "switching provider is a config change"
/// has to mean to be worth claiming.
/// </para>
/// <para>
/// <c>ProviderSwitchTests</c> already covers construction — which client type comes back for
/// which setting. It never calls one. These run the debate to a finished audit, so the live
/// branches are exercised end to end: credential resolution, URL shaping, the request the
/// provider actually receives, and the translation of its reply back into a debate turn.
/// </para>
/// </remarks>
public class ProviderDebateTests
{
    /// <summary>
    /// Everything from configuration to a finished audit, exactly as the API does it.
    /// </summary>
    private static async Task<DebateResult> RunFromConfigurationAsync(
        Dictionary<string, string?> settings, FakeProviderServer? server = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

        var models = ModelOptionsLoader.Load(configuration);
        ProviderReadiness.Verify(models, DebateWorkflow.ModelBackedRoles);

        var factory = new ChatClientFactory(models, server?.AsTransport());
        var workflow = DebateWorkflow.Build(factory, new DebateOptions());

        return await new DebateRunner(workflow).RunAsync(ScanBrief.Stub());
    }

    private static Dictionary<string, string?> Scripted() => new()
    {
        ["SentinelAI:Models:Provider"] = "Scripted",
    };

    private static Dictionary<string, string?> Anthropic() => new()
    {
        ["SentinelAI:Models:Provider"] = "Anthropic",
        ["SentinelAI:Models:ApiKey"] = "test-key-never-leaves-the-process",
    };

    private static Dictionary<string, string?> Azure() => new()
    {
        ["SentinelAI:Models:Provider"] = "AzureOpenAI",
        ["SentinelAI:Models:ApiKey"] = "test-key-never-leaves-the-process",
        ["SentinelAI:Models:Endpoint"] = "https://sentinel-test.openai.azure.com",
        ["SentinelAI:Models:HighTierModel"] = "gpt-4o-audit",     // an Azure deployment name
        ["SentinelAI:Models:CheapTierModel"] = "gpt-4o-mini-audit",
    };

    /// <summary>The same assertions for every provider — the "unchanged" half of the criterion.</summary>
    private static void AssertDebateRanNormally(DebateResult result)
    {
        Assert.NotNull(result.Audit);

        // Order is the contract: Red asserts, Blue validates, Reporter adjudicates.
        Assert.Equal(
            [AgentRole.Red, AgentRole.Blue, AgentRole.Reporter],
            result.Audit!.Transcript.Select(t => t.Role));

        // In character, by the marker each role's own instructions mandate and no other role's:
        // Red asserts hops, Blue closes with the verdict token, the Reporter grades the result.
        Assert.Contains("HOP 1:", result.Audit.Transcript[0].Content);
        Assert.Contains(BlueTeamExecutor.HoldsVerdict, result.Audit.Transcript[1].Content);
        Assert.Contains("SEVERITY:", result.Audit.Summary);

        Assert.True(result.Audit.Converged);
        Assert.False(result.Audit.TerminatedByTurnCap);
    }

    [Fact]
    public async Task The_debate_runs_on_the_offline_provider()
    {
        AssertDebateRanNormally(await RunFromConfigurationAsync(Scripted()));
    }

    [Fact]
    public async Task The_same_debate_runs_on_a_live_openai_wire_provider()
    {
        var server = new FakeProviderServer();

        AssertDebateRanNormally(await RunFromConfigurationAsync(Anthropic(), server));

        // It genuinely went over the wire client rather than falling back to Scripted.
        Assert.NotEmpty(server.Calls);
        Assert.All(server.Calls, c => Assert.Equal("Bearer", c.AuthorizationScheme));
    }

    [Fact]
    public async Task The_same_debate_runs_on_azure()
    {
        var server = new FakeProviderServer();

        AssertDebateRanNormally(await RunFromConfigurationAsync(Azure(), server));

        Assert.NotEmpty(server.Calls);
    }

    /// <summary>
    /// The criterion itself, as one assertion: two providers, one config key apart, same audit.
    /// </summary>
    [Fact]
    public async Task Switching_provider_by_configuration_alone_changes_nothing_about_the_debate()
    {
        var offline = await RunFromConfigurationAsync(Scripted());
        var live = await RunFromConfigurationAsync(Anthropic(), new FakeProviderServer());

        // Not the same words — different providers say different things — but the same debate:
        // same agents, same order, same termination path, same shape of audit.
        Assert.Equal(
            offline.Audit!.Transcript.Select(t => t.Role),
            live.Audit!.Transcript.Select(t => t.Role));
        Assert.Equal(offline.Audit.Converged, live.Audit.Converged);
        Assert.Equal(offline.Audit.TerminatedByTurnCap, live.Audit.TerminatedByTurnCap);
        Assert.Equal(offline.Audit.Transcript.Count, live.Audit.Transcript.Count);
    }

    /// <summary>
    /// Each agent is asked with its own persona, whichever provider is answering. A regression
    /// here is how every role ended up returning the same fallback string once before.
    /// </summary>
    [Fact]
    public async Task Every_agent_reaches_the_provider_in_character()
    {
        var server = new FakeProviderServer();

        await RunFromConfigurationAsync(Anthropic(), server);

        Assert.NotEmpty(server.CallsFor(AgentRole.Red));
        Assert.NotEmpty(server.CallsFor(AgentRole.Blue));
        Assert.NotEmpty(server.CallsFor(AgentRole.Reporter));
    }

    /// <summary>
    /// The tier map is policy, not provider detail: it must survive a provider switch. Red is
    /// a reasoning turn (High) and the Orchestrator is routine (Cheap), so the two must reach
    /// the provider under different model ids.
    /// </summary>
    [Fact]
    public async Task Tier_routing_survives_the_switch_to_a_live_provider()
    {
        var server = new FakeProviderServer();
        var settings = Anthropic();
        settings["SentinelAI:Models:HighTierModel"] = "high-tier-model";
        settings["SentinelAI:Models:CheapTierModel"] = "cheap-tier-model";

        await RunFromConfigurationAsync(settings, server);

        Assert.All(server.CallsFor(AgentRole.Red), c => Assert.Contains("high-tier-model", c.Body));
        Assert.All(server.CallsFor(AgentRole.Orchestrator), c => Assert.Contains("cheap-tier-model", c.Body));
    }

    /// <summary>
    /// A per-agent key is a SEC-02 feature that only pays off if it reaches the provider. If
    /// the shared key were sent instead, per-agent rate limits and cost attribution are fiction.
    /// </summary>
    [Fact]
    public async Task Per_agent_credentials_reach_the_provider()
    {
        var server = new FakeProviderServer();
        var settings = Anthropic();
        settings["SentinelAI:Models:Agents:Red:ApiKey"] = "red-only-key";

        await RunFromConfigurationAsync(settings, server);

        Assert.All(server.CallsFor(AgentRole.Red),
            c => Assert.Equal("red-only-key", c.AuthorizationValue));
        Assert.All(server.CallsFor(AgentRole.Blue),
            c => Assert.Equal("test-key-never-leaves-the-process", c.AuthorizationValue));
    }
}

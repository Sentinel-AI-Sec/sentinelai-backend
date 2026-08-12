using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// The startup preflight (SEC-30): a provider that cannot serve a debate must say so while the
/// host is booting, not on the first model call.
/// </summary>
/// <remarks>
/// The failure this prevents is expensive precisely because everything before it looks healthy.
/// The API starts, <c>POST /v1/scans</c> answers <c>202 Accepted</c>, the bundle is written to
/// disk and the job row is committed — and only then does a missing key surface, inside a
/// debate turn, after the caller has been told the scan was accepted. Every fact needed to
/// refuse at boot was already in configuration.
/// </remarks>
public class ProviderReadinessTests
{
    private static string? Check(ModelProviderOptions options) =>
        ProviderReadiness.Describe(options, DebateWorkflow.ModelBackedRoles);

    [Fact]
    public void The_offline_provider_is_always_ready()
    {
        // A fresh clone has no credentials at all and must still run.
        Assert.Null(Check(new ModelProviderOptions()));
        //Assert.NotNull(Check(new ModelProviderOptions()));

    }

    [Fact]
    public void A_live_provider_with_a_shared_key_is_ready()
    {
        Assert.Null(Check(new ModelProviderOptions
        {
            Provider = ModelProvider.Anthropic,
            ApiKey = "shared",
        }));
    }

    [Fact]
    public void A_live_provider_with_no_key_names_every_agent_that_lacks_one()
    {
        var problem = Check(new ModelProviderOptions { Provider = ModelProvider.Nim });

        Assert.NotNull(problem);
        foreach (var role in DebateWorkflow.ModelBackedRoles)
            Assert.Contains(role.ToString(), problem, StringComparison.Ordinal);

        // The message has to say what to do, not just that something is wrong.
        Assert.Contains($"{ModelProviderOptions.SectionName}:ApiKey", problem, StringComparison.Ordinal);
        Assert.Contains(ModelOptionsLoader.SharedKeyVariable, problem, StringComparison.Ordinal);
    }

    [Fact]
    public void One_agent_missing_a_key_is_still_a_failure()
    {
        // Per-agent keys mean "all four", not "at least one": a debate that reaches Blue and
        // then dies has already spent Red's tokens.
        var options = new ModelProviderOptions { Provider = ModelProvider.Anthropic };
        foreach (var role in DebateWorkflow.ModelBackedRoles.Where(r => r != AgentRole.Blue))
            options.Agents[role] = new AgentModelOptions { ApiKey = "per-agent" };

        var problem = Check(options);

        Assert.NotNull(problem);
        Assert.Contains(nameof(AgentRole.Blue), problem, StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(AgentRole.Red), problem, StringComparison.Ordinal);
    }

    [Fact]
    public void Azure_without_an_endpoint_is_not_ready_even_with_a_key()
    {
        var problem = Check(new ModelProviderOptions
        {
            Provider = ModelProvider.AzureOpenAI,
            ApiKey = "shared",
        });

        Assert.NotNull(problem);
        Assert.Contains("Endpoint", problem, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Azure_with_an_endpoint_and_a_key_is_ready()
    {
        Assert.Null(Check(new ModelProviderOptions
        {
            Provider = ModelProvider.AzureOpenAI,
            ApiKey = "shared",
            Endpoint = "https://sentinel-test.openai.azure.com",
        }));
    }

    [Fact]
    public void A_whitespace_key_counts_as_absent()
    {
        // An unfilled placeholder in dev.json must not be mistaken for a credential and sent.
        var problem = Check(new ModelProviderOptions
        {
            Provider = ModelProvider.Anthropic,
            ApiKey = "   ",
        });

        Assert.NotNull(problem);
    }

    [Fact]
    public void Verify_throws_with_the_same_message_Describe_reports()
    {
        var options = new ModelProviderOptions { Provider = ModelProvider.Nim };

        var ex = Assert.Throws<InvalidOperationException>(
            () => ProviderReadiness.Verify(options, DebateWorkflow.ModelBackedRoles));

        Assert.Equal(Check(options), ex.Message);
    }
}

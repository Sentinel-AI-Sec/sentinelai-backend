using Microsoft.Extensions.AI;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// Azure OpenAI is the production provider in AID-01 section 2, and it does not speak the
/// same protocol as the OpenAI-compatible ones. These assert the three differences that a
/// plain <c>OpenAIClient</c> gets wrong.
/// </summary>
/// <remarks>
/// <para>
/// The branch was previously built as an <c>OpenAIClient</c> pointed at the Azure host. That
/// sends <c>Authorization: Bearer</c> to <c>{endpoint}/chat/completions</c> with the model in
/// the body — none of which Azure accepts. It could never have authenticated, and no test
/// caught it because every provider test stopped at the type of the object returned.
/// </para>
/// <para>
/// So these tests assert on the <em>request that reaches the provider</em>. That is the level
/// at which "the provider is configured correctly" is a checkable claim rather than a hope.
/// </para>
/// </remarks>
public class AzureProviderTests
{
    private const string Endpoint = "https://sentinel-test.openai.azure.com";
    private const string Key = "test-key-never-leaves-the-process";

    private static async Task<ProviderCall> CallAsync(
        ModelProviderOptions options, FakeProviderServer server, AgentRole role = AgentRole.Red)
    {
        var client = new ChatClientFactory(options, server.AsTransport()).Create(role, ModelTier.High);
        await client.GetResponseAsync([new ChatMessage(ChatRole.User, "go")]);
        return Assert.Single(server.Calls);
    }

    private static ModelProviderOptions AzureOptions() => new()
    {
        Provider = ModelProvider.AzureOpenAI,
        Endpoint = Endpoint,
        ApiKey = Key,
        HighTierModel = "gpt-4o-audit",
    };

    [Fact]
    public async Task The_deployment_name_goes_in_the_url_path()
    {
        // Azure has no "model" parameter the way OpenAI does: you address a deployment you
        // created and named, and the name is part of the route.
        var call = await CallAsync(AzureOptions(), new FakeProviderServer());

        Assert.Contains("/openai/deployments/gpt-4o-audit/chat/completions", call.Uri.AbsolutePath,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Every_request_carries_an_api_version()
    {
        // Azure rejects a request without one; the OpenAI-compatible providers have no such
        // concept, which is why this cannot be shared with them.
        var call = await CallAsync(AzureOptions(), new FakeProviderServer());

        Assert.Contains("api-version=", call.Uri.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Authentication_is_the_api_key_header_not_bearer()
    {
        var call = await CallAsync(AzureOptions(), new FakeProviderServer());

        Assert.Equal(Key, call.ApiKeyHeader);
        Assert.Null(call.AuthorizationScheme);
    }

    [Fact]
    public async Task An_openai_compatible_provider_still_uses_bearer_and_no_deployment_path()
    {
        // The contrast that makes the three assertions above meaningful: the same factory,
        // one config value different, and a completely different request shape.
        var options = new ModelProviderOptions
        {
            Provider = ModelProvider.Anthropic,
            ApiKey = Key,
            HighTierModel = "claude-sonnet-5",
        };

        var call = await CallAsync(options, new FakeProviderServer());

        Assert.Equal("Bearer", call.AuthorizationScheme);
        Assert.Equal(Key, call.AuthorizationValue);
        Assert.Null(call.ApiKeyHeader);
        Assert.DoesNotContain("/deployments/", call.Uri.AbsolutePath, StringComparison.Ordinal);

        // OpenAI takes the model in the body instead.
        Assert.Contains("claude-sonnet-5", call.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_per_agent_deployment_override_reaches_the_url()
    {
        // Roles can be pinned to different Azure deployments — a cheaper one for routine
        // turns, or a separately quota'd deployment for the agent that does the most work.
        var options = AzureOptions();
        options.Agents[AgentRole.Blue] = new AgentModelOptions { Model = "blue-dedicated-deployment" };

        var call = await CallAsync(options, new FakeProviderServer(), AgentRole.Blue);

        Assert.Contains("/openai/deployments/blue-dedicated-deployment/", call.Uri.AbsolutePath,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Azure_without_an_endpoint_fails_loud_naming_the_setting()
    {
        // There is no default: the host contains the customer's own resource name. Guessing
        // one would produce a DNS failure at the first debate turn instead of a clear message.
        var factory = new ChatClientFactory(new ModelProviderOptions
        {
            Provider = ModelProvider.AzureOpenAI,
            ApiKey = Key,
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => factory.Create(AgentRole.Red, ModelTier.High));

        Assert.Contains("endpoint", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"{ModelProviderOptions.SectionName}:Endpoint", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Azure_reports_a_missing_key_before_it_complains_about_the_endpoint()
    {
        // Both are missing here. The key is reported because it is the one the caller almost
        // always forgot; reporting whichever setting happened to be read first makes the
        // error depend on implementation order rather than on what is wrong.
        var factory = new ChatClientFactory(new ModelProviderOptions
        {
            Provider = ModelProvider.AzureOpenAI,
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => factory.Create(AgentRole.Red, ModelTier.High));

        Assert.Contains("API key", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}

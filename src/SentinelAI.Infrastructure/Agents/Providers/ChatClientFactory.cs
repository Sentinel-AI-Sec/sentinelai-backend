using System.ClientModel;
using System.ClientModel.Primitives;
using System.Collections.Concurrent;
using Azure.AI.OpenAI;
using Microsoft.Extensions.AI;
using OpenAI;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Agents.Providers;

/// <summary>
/// Builds the <see cref="IChatClient"/> the agents talk to, per configured provider and
/// model tier. This is the single seam AID-01 section 2 promises: switching provider is
/// a config change, not a code change.
/// </summary>
public interface IChatClientFactory
{
    /// <summary>
    /// Builds the client for one agent. The role is supplied so offline providers can
    /// answer in character, and so a provider may later route roles to different models.
    /// </summary>
    IChatClient Create(AgentRole role, ModelTier tier);
}

/// <inheritdoc />
/// <param name="options">Provider, credentials, endpoints and tier models.</param>
/// <param name="transport">
/// Replaces the HTTP stack under a <em>live</em> provider. Null in production — the only
/// caller that supplies one is the test that runs a full debate over the real OpenAI-wire
/// client without a network (SEC-30).
/// </param>
/// <remarks>
/// The transport parameter is a deliberate seam rather than a leak. Before it, the live
/// branches of this factory could only be tested by asserting the <em>type</em> of the
/// client that came back, because calling one required a real endpoint and a real key —
/// which is how the Azure branch stayed wrong for a whole sprint without a test noticing.
/// Substituting the transport exercises everything above it: credential resolution,
/// endpoint shaping, deployment naming, retry policy, and response translation.
/// </remarks>
public sealed class ChatClientFactory(ModelProviderOptions options, PipelineTransport? transport = null)
    : IChatClientFactory
{
    private const string NimDefaultEndpoint = "https://integrate.api.nvidia.com/v1";
    private const string AnthropicDefaultEndpoint = "https://api.anthropic.com/v1";

    private readonly ModelProviderOptions _options =
        options ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Remote clients, reused across debates.
    /// </summary>
    /// <remarks>
    /// A workflow is built per scan, so without this every request constructed four fresh
    /// <see cref="OpenAIClient"/>s, threw away their connection pools, and left them
    /// undisposed. Caching is safe because the client is stateless per call and the
    /// credential is fixed per role: the key covers everything that varies.
    /// </remarks>
    private readonly ConcurrentDictionary<(AgentRole Role, ModelTier Tier), IChatClient> _remote = new();

    public IChatClient Create(AgentRole role, ModelTier tier) => _options.Provider switch
    {
        // Deliberately not cached. ScriptedChatClient records call counts and every request
        // it saw for test assertions, so a shared instance would make those cumulative
        // across runs and quietly break the checkpoint-resume assertions.
        ModelProvider.Scripted => new ScriptedChatClient(role),

        // Azure speaks the OpenAI *format* but not the OpenAI *protocol* — different auth
        // header, and the model name is a deployment in the URL path. It needs its own client.
        ModelProvider.AzureOpenAI => _remote.GetOrAdd((role, tier), key => Azure(key.Role, key.Tier)),

        // A failure here propagates without being cached, so a missing credential still
        // fails loud on every attempt rather than once.
        ModelProvider.Nim or ModelProvider.Anthropic =>
            _remote.GetOrAdd((role, tier), key => OpenAICompatible(key.Role, key.Tier)),

        _ => throw new NotSupportedException($"Unknown provider '{_options.Provider}'.")
    };

    /// <summary>
    /// NIM and Anthropic's compat endpoint both speak the OpenAI wire format, so they share
    /// one client and differ only by credential, base URL and model.
    /// </summary>
    /// <remarks>
    /// Each agent gets its own <see cref="OpenAIClient"/>, so per-agent keys are genuinely
    /// separate connections rather than one client with a swapped header.
    /// </remarks>
    private IChatClient OpenAICompatible(AgentRole role, ModelTier tier)
    {
        // Credentials are checked before anything else, so a misconfigured provider always
        // reports the missing key rather than whichever setting happened to be read first.
        var key = RequireKey(role);
        var endpoint = new Uri(_options.EndpointFor(role) ?? DefaultEndpointFor(_options.Provider));

        // Without an explicit ceiling a stalled provider hangs the debate indefinitely
        // with no output and no error — which looks exactly like the run being slow.
        // The retry cap matters just as much: the default policy turns one timed-out call
        // into four, so the ceiling silently becomes 4x what was configured.
        var clientOptions = new OpenAIClientOptions
        {
            Endpoint = endpoint,
            NetworkTimeout = _options.RequestTimeout,
            RetryPolicy = new DebateRetryPolicy(maxRetries: _options.MaxRetries)
        };

        if (transport is not null) clientOptions.Transport = transport;

        return new OpenAIClient(new ApiKeyCredential(key), clientOptions)
            .GetChatClient(_options.ModelFor(role, tier))
            .AsIChatClient();
    }

    /// <summary>
    /// Azure OpenAI — the production target in AID-01 section 2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Azure differs from the OpenAI-compatible providers in three load-bearing ways, and
    /// this method exists because getting any of them wrong produces a 401 or a 404 rather
    /// than a useful error:
    /// </para>
    /// <list type="number">
    ///   <item>Authentication is an <c>api-key</c> header, not <c>Authorization: Bearer</c>.</item>
    ///   <item>The model is a <em>deployment name</em> you chose, and it appears in the URL
    ///   path (<c>/openai/deployments/{name}/chat/completions</c>) rather than in the body.</item>
    ///   <item>Every request carries an <c>api-version</c> query parameter.</item>
    /// </list>
    /// <para>
    /// <see cref="AzureOpenAIClient"/> applies all three. The previous implementation built a
    /// plain <see cref="OpenAIClient"/> pointed at the Azure host, which gets none of them
    /// right — it was declared as the production provider and could never have authenticated.
    /// </para>
    /// </remarks>
    private IChatClient Azure(AgentRole role, ModelTier tier)
    {
        var key = RequireKey(role);

        // No default is possible: the host contains the customer's own resource name.
        var endpoint = _options.EndpointFor(role)
            ?? throw new InvalidOperationException(
                $"Azure OpenAI needs an explicit endpoint. Set {ModelProviderOptions.SectionName}:Endpoint "
                + "to your resource URL, e.g. https://my-resource.openai.azure.com.");

        var clientOptions = new AzureOpenAIClientOptions
        {
            NetworkTimeout = _options.RequestTimeout,
            RetryPolicy = new DebateRetryPolicy(maxRetries: _options.MaxRetries)
        };

        if (transport is not null) clientOptions.Transport = transport;

        // For Azure the "model" is the deployment name — see ModelProviderOptions.ModelFor.
        return new AzureOpenAIClient(new Uri(endpoint), new ApiKeyCredential(key), clientOptions)
            .GetChatClient(_options.ModelFor(role, tier))
            .AsIChatClient();
    }

    /// <summary>
    /// The agent's credential, or a message naming the exact settings that would supply one.
    /// Never silently degrades to an unauthenticated call or back to the scripted client.
    /// </summary>
    private string RequireKey(AgentRole role) =>
        _options.ApiKeyFor(role)
        ?? throw new InvalidOperationException(
            $"Agent '{role}' has no API key for provider '{_options.Provider}'. Set "
            + $"{ModelProviderOptions.SectionName}:Agents:{role}:ApiKey for this agent, "
            + $"or {ModelProviderOptions.SectionName}:ApiKey to share one across all agents.");

    /// <summary>
    /// Fails loud rather than guessing — the same "no silent fallback" guard AID-01
    /// section 5 mandates for the embedder.
    /// </summary>
    private static string DefaultEndpointFor(ModelProvider provider) => provider switch
    {
        ModelProvider.Nim => NimDefaultEndpoint,
        ModelProvider.Anthropic => AnthropicDefaultEndpoint,
        _ => throw new NotSupportedException($"Unknown provider '{provider}'.")
    };
}

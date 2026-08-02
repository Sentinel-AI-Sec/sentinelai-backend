using System.ClientModel;
using System.ClientModel.Primitives;
using System.Collections.Concurrent;
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
public sealed class ChatClientFactory(ModelProviderOptions options) : IChatClientFactory
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

        // A failure here propagates without being cached, so a missing credential still
        // fails loud on every attempt rather than once.
        ModelProvider.Nim or ModelProvider.Anthropic or ModelProvider.AzureOpenAI =>
            _remote.GetOrAdd((role, tier), key => OpenAICompatible(key.Role, key.Tier)),

        _ => throw new NotSupportedException($"Unknown provider '{_options.Provider}'.")
    };

    /// <summary>
    /// NIM, Anthropic's compat endpoint, and Azure OpenAI all speak the OpenAI wire
    /// format, so they share one client and differ only by credential, base URL and model.
    /// </summary>
    /// <remarks>
    /// Each agent gets its own <see cref="OpenAIClient"/>, so per-agent keys are genuinely
    /// separate connections rather than one client with a swapped header.
    /// </remarks>
    private IChatClient OpenAICompatible(AgentRole role, ModelTier tier)
    {
        // Credentials are checked before anything else, so a misconfigured provider always
        // reports the missing key rather than whichever setting happened to be read first.
        var key = _options.ApiKeyFor(role)
            ?? throw new InvalidOperationException(
                $"Agent '{role}' has no API key for provider '{_options.Provider}'. Set "
                + $"{ModelProviderOptions.SectionName}:Agents:{role}:ApiKey for this agent, "
                + $"or {ModelProviderOptions.SectionName}:ApiKey to share one across all agents.");

        var endpoint = new Uri(_options.EndpointFor(role) ?? DefaultEndpointFor(_options.Provider));

        // Without an explicit ceiling a stalled provider hangs the debate indefinitely
        // with no output and no error — which looks exactly like the run being slow.
        // The retry cap matters just as much: the default policy turns one timed-out call
        // into four, so the ceiling silently becomes 4x what was configured.
        var client = new OpenAIClient(
            new ApiKeyCredential(key),
            new OpenAIClientOptions
            {
                Endpoint = endpoint,
                NetworkTimeout = _options.RequestTimeout,
                RetryPolicy = new DebateRetryPolicy(maxRetries: _options.MaxRetries)
            });

        return client.GetChatClient(_options.ModelFor(role, tier)).AsIChatClient();
    }

    /// <summary>
    /// Fails loud rather than guessing — the same "no silent fallback" guard AID-01
    /// section 5 mandates for the embedder.
    /// </summary>
    private static string DefaultEndpointFor(ModelProvider provider) => provider switch
    {
        ModelProvider.Nim => NimDefaultEndpoint,
        ModelProvider.Anthropic => AnthropicDefaultEndpoint,
        ModelProvider.AzureOpenAI => throw new InvalidOperationException(
            $"Azure OpenAI needs an explicit endpoint. Set {ModelProviderOptions.SectionName}:Endpoint."),
        _ => throw new NotSupportedException($"Unknown provider '{provider}'.")
    };
}

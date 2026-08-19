using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Agents.Providers;

/// <summary>
/// Which backing model provider the agents talk to. AID-01 section 2 requires the model
/// to sit behind a connector abstraction so switching provider is a config change.
/// </summary>
public enum ModelProvider
{
    /// <summary>
    /// Deterministic offline canned responses. The default, and what every unit test
    /// runs against — no network, no keys, no cost.
    /// </summary>
    Scripted,

    /// <summary>NVIDIA NIM. OpenAI-wire-compatible, so it reuses the OpenAI client.</summary>
    Nim,

    /// <summary>Anthropic Claude, via an OpenAI-compatible gateway.</summary>
    Anthropic,

    /// <summary>Azure OpenAI — the production target in AID-01 section 2.</summary>
    AzureOpenAI
}

/// <summary>
/// Credentials and model choice for a single agent, overriding the shared defaults.
/// </summary>
public sealed class AgentModelOptions
{
    /// <summary>This agent's own API key.</summary>
    public string? ApiKey { get; set; }

    /// <summary>Endpoint override, if this agent talks to a different deployment.</summary>
    public string? Endpoint { get; set; }

    /// <summary>Model id override, ignoring the tier default.</summary>
    public string? Model { get; set; }
}

/// <summary>
/// Bound from configuration section <c>SentinelAI:Models</c>.
/// </summary>
public sealed class ModelProviderOptions
{
    public const string SectionName = "SentinelAI:Models";

    public ModelProvider Provider { get; set; } = ModelProvider.Scripted;

    /// <summary>
    /// Base URL of the OpenAI-compatible endpoint. Ignored for <see cref="ModelProvider.Scripted"/>.
    /// Defaults are filled in per-provider by <see cref="ChatClientFactory"/> when left null.
    /// </summary>
    public string? Endpoint { get; set; }

    /// <summary>
    /// Shared fallback API key, used by any agent without one of its own. Never commit
    /// this — supply via <c>dev.json</c>, user-secrets, or the environment.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// Per-agent credentials, keyed by role — one entry per agent in AID-01 §3.1.
    /// </summary>
    /// <remarks>
    /// <para>Giving each agent its own key buys three things a single shared key cannot:</para>
    /// <list type="bullet">
    ///   <item>Rate limits are isolated. On a per-key quota such as NIM's, a Red agent
    ///   looping inside the turn-cap cannot exhaust the budget Blue needs to rebut it.</item>
    ///   <item>Spend is attributable. AID-01 §2 tracks cost per audit by model tier; per-agent
    ///   keys make that measurable per role without extra instrumentation.</item>
    ///   <item>A leaked key is rotated for one agent, not for the whole debate.</item>
    /// </list>
    /// <para>
    /// Any agent without an entry falls back to <see cref="ApiKey"/>, so a single shared
    /// key still works for local runs.
    /// </para>
    /// </remarks>
    public IDictionary<AgentRole, AgentModelOptions> Agents { get; } =
        new Dictionary<AgentRole, AgentModelOptions>();

    /// <summary>
    /// Per-call network ceiling, applied to the underlying HTTP pipeline. Without it a
    /// stalled provider hangs the whole debate with no output and no error, which is
    /// indistinguishable from the run being slow.
    /// </summary>
    /// <remarks>
    /// This is the only request timeout. It lives here rather than on <c>DebateOptions</c>
    /// because the client is built before the debate options are in scope — a second copy
    /// over there was bound from configuration and read by nothing.
    /// </remarks>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(120);

    /// <summary>
    /// Retries per model call, applied by <see cref="DebateRetryPolicy"/> to transient
    /// server errors only — never to a timeout.
    /// </summary>
    /// <remarks>
    /// Capping this alone is not enough, which is why the policy is custom. Retrying a
    /// timeout multiplied a 120s ceiling into a measured 480s hang; refusing to retry a
    /// transient 503 cost a completed debate its Reporter turn. The count applies to the
    /// second case, where retrying is cheap and usually works.
    /// </remarks>
    public int MaxRetries { get; set; } = 3;

    /// <summary>
    /// Model id for reasoning-heavy turns. Under <see cref="ModelProvider.AzureOpenAI"/> this
    /// is the <em>deployment name</em>, not the model name — see <see cref="ModelFor(ModelTier)"/>.
    /// </summary>
    public string? HighTierModel { get; set; }

    /// <summary>
    /// Model id for routine turns. Under <see cref="ModelProvider.AzureOpenAI"/> this is the
    /// <em>deployment name</em> — see <see cref="ModelFor(ModelTier)"/>.
    /// </summary>
    public string? CheapTierModel { get; set; }

    /// <summary>This agent's overrides, if any were configured.</summary>
    public AgentModelOptions? For(AgentRole role) =>
        Agents.TryGetValue(role, out var agent) ? agent : null;

    /// <summary>The agent's own key, else the shared one, else null.</summary>
    public string? ApiKeyFor(AgentRole role) => Blank(For(role)?.ApiKey) ?? Blank(ApiKey);

    /// <summary>The agent's own endpoint, else the shared one, else null.</summary>
    public string? EndpointFor(AgentRole role) => Blank(For(role)?.Endpoint) ?? Blank(Endpoint);

    /// <summary>The agent's own model, else the tier default.</summary>
    public string ModelFor(AgentRole role, ModelTier tier) =>
        Blank(For(role)?.Model) ?? ModelFor(tier);

    /// <summary>Reports which agents are missing a usable key. Empty means ready to run.</summary>
    public IReadOnlyList<AgentRole> AgentsMissingKeys(IEnumerable<AgentRole> required) =>
        [.. required.Where(role => ApiKeyFor(role) is null)];

    /// <summary>
    /// Resolves the model id for a tier, falling back to the provider default.
    /// </summary>
    /// <remarks>
    /// For <see cref="ModelProvider.AzureOpenAI"/> the returned string is a <em>deployment
    /// name</em>. Azure has no way to ask for "gpt-4o" by name: you create a deployment,
    /// choose its name yourself, and that name goes in the request path. The defaults below
    /// assume the deployment was named after the model it serves, which is the usual
    /// convention — if yours is called something else, set <see cref="HighTierModel"/> and
    /// <see cref="CheapTierModel"/> to the deployment names rather than to model ids.
    /// </remarks>
    public string ModelFor(ModelTier tier) => tier switch
    {
        ModelTier.High => HighTierModel ?? DefaultHighTier(Provider),
        ModelTier.Cheap => CheapTierModel ?? DefaultCheapTier(Provider),
        _ => throw new ArgumentOutOfRangeException(nameof(tier))
    };

    /// <summary>
    /// Treats whitespace as absent, so an unfilled <c>dev.json</c> placeholder falls through
    /// to the next source instead of being sent as a credential.
    /// </summary>
    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static string DefaultHighTier(ModelProvider p) => p switch
    {
        ModelProvider.Nim => "meta/llama-3.3-70b-instruct",
        ModelProvider.Anthropic => "claude-sonnet-5",
        ModelProvider.AzureOpenAI => "gpt-4o",
        _ => "scripted-high"
    };

    private static string DefaultCheapTier(ModelProvider p) => p switch
    {
        ModelProvider.Nim => "meta/llama-3.1-8b-instruct",
        ModelProvider.Anthropic => "claude-haiku-4-5-20251001",
        ModelProvider.AzureOpenAI => "gpt-4o-mini",
        _ => "scripted-cheap"
    };
}

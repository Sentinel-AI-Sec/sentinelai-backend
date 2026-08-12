using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Agents.Providers;

/// <summary>
/// Checks, at startup, that the configured provider could actually serve a debate (SEC-30).
/// </summary>
/// <remarks>
/// <para>
/// Without this the cost of a misconfiguration is paid at the worst possible moment. The API
/// starts cleanly, <c>POST /v1/scans</c> returns <c>202 Accepted</c>, the bundle is stored,
/// the job is queued — and then the first model call throws deep inside a debate turn, after
/// the caller has been told everything is fine. The information needed to prevent all of that
/// was available before the host finished booting.
/// </para>
/// <para>
/// <see cref="ModelProvider.Scripted"/> is always ready: it is offline by definition, which is
/// what lets a fresh clone run with no credentials at all.
/// </para>
/// </remarks>
public static class ProviderReadiness
{
    /// <summary>
    /// Describes why a provider cannot run, or <c>null</c> when it can.
    /// </summary>
    /// <param name="options">The loaded provider configuration.</param>
    /// <param name="requiredRoles">
    /// The agents that will make a model call — <c>DebateWorkflow.ModelBackedRoles</c>.
    /// Passed in rather than assumed so the check cannot drift from the workflow it guards.
    /// </param>
    public static string? Describe(ModelProviderOptions options, IEnumerable<AgentRole> requiredRoles)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(requiredRoles);

        if (options.Provider == ModelProvider.Scripted)
            return null;

        var missing = options.AgentsMissingKeys(requiredRoles);
        if (missing.Count > 0)
        {
            return $"Provider '{options.Provider}' is configured but "
                   + $"{string.Join(", ", missing)} {(missing.Count == 1 ? "has" : "have")} no API key. "
                   + $"Set {ModelProviderOptions.SectionName}:ApiKey to share one key across all agents, "
                   + $"or {ModelProviderOptions.SectionName}:Agents:<Role>:ApiKey per agent "
                   + $"(environment: {ModelOptionsLoader.SharedKeyVariable}, "
                   + $"or {ModelOptionsLoader.KeyVariableFor(missing[0])} for one agent).";
        }

        // Azure's host contains the customer's own resource name, so unlike NIM and Anthropic
        // there is no default that could stand in for it.
        if (options.Provider == ModelProvider.AzureOpenAI && options.Endpoint is null or "")
        {
            return $"Provider 'AzureOpenAI' needs an explicit endpoint. Set "
                   + $"{ModelProviderOptions.SectionName}:Endpoint to your resource URL, "
                   + "e.g. https://my-resource.openai.azure.com.";
        }

        return null;
    }

    /// <summary>
    /// Throws if the configured provider could not serve a debate. Called during service
    /// registration so the failure lands at boot, naming what is missing.
    /// </summary>
    public static void Verify(ModelProviderOptions options, IEnumerable<AgentRole> requiredRoles)
    {
        if (Describe(options, requiredRoles) is { } problem)
            throw new InvalidOperationException(problem);
    }
}

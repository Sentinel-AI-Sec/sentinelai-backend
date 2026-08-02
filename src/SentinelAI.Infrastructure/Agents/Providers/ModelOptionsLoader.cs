using System.Globalization;
using Microsoft.Extensions.Configuration;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Agents.Providers;

/// <summary>
/// Reads <see cref="ModelProviderOptions"/> — including the per-agent keys — out of
/// configuration, then lets environment variables override anything on top.
/// </summary>
/// <remarks>
/// <para>The section is read explicitly rather than via <c>IConfiguration.Bind</c>. Binding
/// an enum-keyed dictionary works but fails silently on a misspelt role name, and a
/// credential that silently fails to load is exactly the failure mode AID-01 §5 warns
/// about. Reading each known role by name means a typo leaves the key absent, and the
/// factory then fails loud naming the agent.</para>
///
/// <para>Precedence, lowest to highest: <c>appsettings.json</c> → <c>dev.json</c> →
/// user-secrets → environment variables. Later sources win, so a shell export always
/// beats a checked-in file.</para>
/// </remarks>
public static class ModelOptionsLoader
{
    /// <summary>Environment variable holding the shared fallback key.</summary>
    public const string SharedKeyVariable = "SENTINELAI_API_KEY";

    /// <summary>The environment variable holding one agent's key, e.g. SENTINELAI_RED_API_KEY.</summary>
    public static string KeyVariableFor(AgentRole role) =>
        $"SENTINELAI_{role.ToString().ToUpperInvariant()}_API_KEY";

    /// <summary>Reads the options from configuration, then applies environment overrides.</summary>
    public static ModelProviderOptions Load(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var section = configuration.GetSection(ModelProviderOptions.SectionName);

        var options = new ModelProviderOptions
        {
            Endpoint = section["Endpoint"],
            ApiKey = section["ApiKey"],
            HighTierModel = section["HighTierModel"],
            CheapTierModel = section["CheapTierModel"]
        };

        if (Enum.TryParse<ModelProvider>(section["Provider"], ignoreCase: true, out var provider))
            options.Provider = provider;

        // Read explicitly like everything else on this type. Omitting them meant the two
        // settings that bound how long a stalled provider can hang the debate — and how many
        // times a failed call is repeated — silently kept their defaults no matter what
        // configuration said.
        if (TimeSpan.TryParse(section["RequestTimeout"], CultureInfo.InvariantCulture, out var timeout)
            && timeout > TimeSpan.Zero)
            options.RequestTimeout = timeout;

        if (int.TryParse(section["MaxRetries"], CultureInfo.InvariantCulture, out var retries)
            && retries >= 0)
            options.MaxRetries = retries;

        // Every role is read by name, so an unrecognised key in the file is simply ignored
        // rather than quietly becoming an agent nobody configured.
        foreach (var role in Enum.GetValues<AgentRole>())
        {
            var agent = section.GetSection("Agents").GetSection(role.ToString());

            var configured = new AgentModelOptions
            {
                ApiKey = agent["ApiKey"],
                Endpoint = agent["Endpoint"],
                Model = agent["Model"]
            };

            if (configured is { ApiKey: null, Endpoint: null, Model: null }) continue;
            options.Agents[role] = configured;
        }

        ApplyEnvironmentOverrides(options);
        return options;
    }

    /// <summary>
    /// Lets <c>SENTINELAI_API_KEY</c> and <c>SENTINELAI_&lt;ROLE&gt;_API_KEY</c> override
    /// whatever the files supplied. Useful in CI, where secrets arrive as env vars.
    /// </summary>
    public static void ApplyEnvironmentOverrides(ModelProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (Value(SharedKeyVariable) is { } shared) options.ApiKey = shared;
        if (Value("SENTINELAI_ENDPOINT") is { } endpoint) options.Endpoint = endpoint;
        if (Value("SENTINELAI_MODEL") is { } model) options.HighTierModel = model;

        foreach (var role in Enum.GetValues<AgentRole>())
        {
            if (Value(KeyVariableFor(role)) is not { } key) continue;

            if (!options.Agents.TryGetValue(role, out var agent))
                options.Agents[role] = agent = new AgentModelOptions();

            agent.ApiKey = key;
        }
    }

    private static string? Value(string variable)
    {
        var value = Environment.GetEnvironmentVariable(variable);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}

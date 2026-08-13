using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Debate;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Infrastructure.Agents;

/// <summary>
/// Registers the Red/Blue/Reporter debate. Split from the root
/// <c>DependencyInjection</c> so the agent stack can be read — and disabled — on its own.
/// </summary>
public static class AgentsDependencyInjection
{
    public static IServiceCollection AddDebateServices(
        this IServiceCollection services,
        IConfiguration configuration
    )
    {
        // Provider, endpoints and the four per-agent credentials.
        //
        // Read through ModelOptionsLoader rather than services.Configure(section). The plain
        // binder is what that loader was written to avoid: it binds the enum-keyed Agents
        // dictionary silently, so "Reperter" in appsettings produces no error and no key,
        // and it never applied the SENTINELAI_<ROLE>_API_KEY overrides that the deployment
        // docs tell people to use. The demo already loaded options this way; the API — the
        // path that actually matters — did not.
        var models = ModelOptionsLoader.Load(configuration);

        // SEC-30: a live provider with no key is a boot-time failure, not a first-debate one.
        // The API used to accept the scan, store the bundle and queue the job before finding
        // out — the demo checked, the path that matters did not.
        ProviderReadiness.Verify(models, DebateWorkflow.ModelBackedRoles);

        // Turn-cap, model tiers, token budget.
        services.Configure<DebateOptions>(configuration.GetSection(DebateOptions.SectionName));

        // Singleton because it caches one remote client per (role, tier) — a workflow is
        // built per scan, so a scoped factory would rebuild those connections every request.
        services.AddSingleton<IChatClientFactory>(_ => new ChatClientFactory(models));

        // SEC-33: nothing resolves the bare engine — IDebateEngine is the redacting wrapper, so
        // the last thing between a brief and a model provider is always a secret scan. Wrapping
        // at registration rather than asking callers to remember is the whole point: a guard you
        // have to opt into is a guard someone eventually forgets.
        services.AddSingleton<DebateEngine>();
        services.AddSingleton<IDebateEngine>(sp => new RedactingDebateEngine(
            sp.GetRequiredService<DebateEngine>(),
            sp.GetRequiredService<ISecretScanner>(),
            sp.GetRequiredService<ILogger<RedactingDebateEngine>>()));

        return services;
    }
}

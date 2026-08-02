using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Debate;
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

        // Turn-cap, model tiers, token budget.
        services.Configure<DebateOptions>(configuration.GetSection(DebateOptions.SectionName));

        // Singleton because it caches one remote client per (role, tier) — a workflow is
        // built per scan, so a scoped factory would rebuild those connections every request.
        services.AddSingleton<IChatClientFactory>(_ => new ChatClientFactory(models));

        services.AddSingleton<IDebateEngine, DebateEngine>();

        return services;
    }
}

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
        this IServiceCollection services, IConfiguration configuration)
    {
        // Provider, endpoints and the four per-agent credentials.
        services.Configure<ModelProviderOptions>(
            configuration.GetSection(ModelProviderOptions.SectionName));

        // Turn-cap, model tiers, token budget, timeout.
        services.Configure<DebateOptions>(
            configuration.GetSection(DebateOptions.SectionName));

        // Singleton: the factory holds no per-request state, and building an OpenAI client
        // per scan would discard its connection pool.
        services.AddSingleton<IChatClientFactory>(sp =>
            new ChatClientFactory(
                sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<ModelProviderOptions>>().Value));

        services.AddSingleton<IDebateEngine, DebateEngine>();

        return services;
    }
}

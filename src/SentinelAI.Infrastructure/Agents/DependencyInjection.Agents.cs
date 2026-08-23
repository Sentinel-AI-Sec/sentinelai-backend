using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Debate;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;
using SentinelAI.Infrastructure.Observability;
using SentinelAI.Infrastructure.Security;

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

        // SEC-31: what a token costs on this provider. Loaded here, next to the provider it
        // is priced against, so nothing downstream has to know which vendor it is billing.
        // Config wins; published list prices fill the gaps; an unpriced tier stays unpriced
        // rather than defaulting to zero and reporting a live debate as free.
        services.AddSingleton(ProviderPricing.Load(configuration, models.Provider));

        // Singleton because it caches one remote client per (role, tier) — a workflow is
        // built per scan, so a scoped factory would rebuild those connections every request.
        services.AddSingleton<IChatClientFactory>(_ => new ChatClientFactory(models));

        // SEC-33: nothing resolves the bare engine — IDebateEngine is the redacting wrapper, so
        // the last thing between a brief and a model provider is always a secret scan. Wrapping
        // at registration rather than asking callers to remember is the whole point: a guard you
        // have to opt into is a guard someone eventually forgets.
        //
        // The scanner is registered here rather than only in the root Infrastructure module
        // because this module is what creates the dependency on it. Leaving it to the root made
        // AddDebateServices insufficient on its own: the app booted fine — the root happens to
        // register both — but a container built from this call alone threw on the first
        // IDebateEngine resolve. TryAdd so a host that has already chosen a scanner keeps it.
        services.TryAddSingleton<ISecretScanner, RegexSecretScanner>();

        // SEC-36: the OTLP exporter, when one is configured. Registered from here rather than
        // from the root module because this is the module that produces the spans — a container
        // built from AddDebateServices alone should trace, for the same reason it should have a
        // secret scanner.
        services.AddSentinelTelemetry(configuration);

        // SEC-36: whether a turn's span may carry its prompt and answer. Resolved through DI
        // rather than read here so there is one loader and one answer — ConfiguredOutboundEndpoints
        // reads the same setting to decide whether the collector is job-content egress, and the
        // two disagreeing would mean prompts exported past a check that never looked at them.
        services.AddSingleton<DebateEngine>(sp => new DebateEngine(
            sp.GetRequiredService<IChatClientFactory>(),
            sp.GetRequiredService<IOptions<DebateOptions>>(),
            sp.GetRequiredService<ModelPricing>(),
            sp.GetRequiredService<TracingOptions>().CaptureContent
                ? TurnTracing.WithContent
                : TurnTracing.MetadataOnly));
        // SEC-50: the mechanical edge check wraps the redacting engine, not the other way
        // around — it inspects what came back from a debate that already ran, so its position
        // relative to the outbound-redaction concern doesn't matter, but IDebateEngine should
        // always resolve to the fully-decorated engine.
        services.AddSingleton<IDebateEngine>(sp => new EdgeIntegrityDebateEngine(
            new RedactingDebateEngine(
                sp.GetRequiredService<DebateEngine>(),
                sp.GetRequiredService<ISecretScanner>(),
                sp.GetRequiredService<ILogger<RedactingDebateEngine>>()),
            sp.GetRequiredService<ILogger<EdgeIntegrityDebateEngine>>()));

        return services;
    }
}

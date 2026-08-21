using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Infrastructure.Agents;
using SentinelAI.Infrastructure.Billing;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Graph;
using SentinelAI.Infrastructure.Knowledge;
using SentinelAI.Infrastructure.Implementation;
using SentinelAI.Infrastructure.Implementation.Repositories;
using SentinelAI.Infrastructure.Normalization;
using SentinelAI.Infrastructure.Orchestration;
using SentinelAI.Infrastructure.Security;

namespace SentinelAI.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<SentinelDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        services.AddDebateServices(configuration);

        // ---- SEC-13: bundle ingest ------------------------------------------------------
        services.AddHttpContextAccessor();
        services.Configure<BundleStorageOptions>(configuration.GetSection(BundleStorageOptions.SectionName));
        services.Configure<CorpusOptions>(configuration.GetSection(CorpusOptions.SectionName));

        // SEC-46: registered by its concrete type as well, because the scan worker has to call
        // Assume() on the very instance the scope's DbContext will read its tenant from. Every
        // consumer other than the worker still takes ICallerContext and still gets the request's
        // own claims — AssumableCallerContext delegates to HttpCallerContext whenever there is a
        // request, and refuses to assume anything when there is one.
        services.AddScoped<AssumableCallerContext>();
        services.AddScoped<ICallerContext>(sp => sp.GetRequiredService<AssumableCallerContext>());
        // SEC-48: the stamp comes from the manifest Pipeline A published, falling back to the
        // configured constant only when this deployment has no manifest to read.
        services.AddScoped<ICorpusVersionProvider, ManifestCorpusVersionProvider>();
        services.AddScoped<IBundleInspector, TarGzBundleInspector>();
        services.AddScoped<IBundleStore, FileSystemBundleStore>();

        // ---- SEC-14: SARIF/JSON normalization -------------------------------------------
        // One extractor per tool, all resolved together as IEnumerable<IFindingExtractor> by
        // the NormalizationPipeline.
        services.AddScoped<IFindingExtractor, RoslynSarifExtractor>();
        services.AddScoped<IFindingExtractor, OsvExtractor>();
        services.AddScoped<IFindingExtractor, TrivySarifExtractor>();
        services.AddScoped<IFindingExtractor, CheckovSarifExtractor>();

        // ---- SEC-15: rule-mapping resolution (exact SQL lookup) --------------------------
        services.AddScoped<IRuleMappingLookup, SqlRuleMappingLookup>();

        // ---- SEC-17: infra spine from the Terraform graph ---------------------------------
        services.AddScoped<IInfraSpineReader, TerraformInfraSpineReader>();

        // ---- SEC-18/19: dep-code, role-resource, and code-infra seams ---------------------
        services.AddScoped<IDepCodeSeamReader, DepCodeSeamReader>();
        services.AddScoped<IRoleResourceSeamReader, RoleResourceSeamReader>();
        services.AddScoped<ICodeInfraSeamReader, CodeInfraSeamReader>();

        // ---- SEC-20: placing infra findings on the resource they are about ----------------
        services.AddScoped<IInfraFindingLocator, TerraformFindingLocator>();

        // ---- SEC-33: the ingress secret gate ----------------------------------------------
        // Singleton and stateless: the compiled patterns are expensive to build and safe to
        // share, and the scanner holds nothing between calls by design — it never retains the
        // text it was given.
        services.AddSingleton<ISecretScanner, RegexSecretScanner>();

        // ---- SEC-34: the egress allowlist and what this deployment is configured to call --
        // Both singletons and both read once: the allowlist is compiled-in vendor hosts plus
        // whatever Security:Egress adds, and the catalog is a snapshot of the endpoints
        // configuration names. EgressAdmission (Application) compares them on every submit.
        services.AddSingleton(_ => EgressPolicyLoader.Load(configuration));
        services.AddSingleton<IOutboundEndpointCatalog>(_ => new ConfiguredOutboundEndpoints(configuration));

        // ---- SEC-45: knowledge retrieval -------------------------------------------------
        // A canned-answer stub so the walking skeleton can cross the retrieval seam before the
        // corpus exists. It logs a warning on every call. Replacing it with the Qdrant
        // retriever (SEC-09) is a change to this line and nothing upstream — which is the
        // property the thin slice was built to establish.

        // ---- SEC-22: the retrieval decision tree ------------------------------------------
        // The tree lives in Application and is pure; these are the two ports it needs. It takes
        // SEC-21's RetrievalQueryBuilder for the query text, so there is one query builder.
        // QdrantKnowledgeSearch is a singleton because QdrantClient is designed to be shared and
        // multiplexes over one gRPC channel.
        // ---- SEC-48: the A-to-B boundary --------------------------------------------------
        // Singleton and read-once: the manifest describes a corpus that was built before this
        // process started and cannot change under it.
        services.Configure<CorpusManifestOptions>(configuration.GetSection(CorpusManifestOptions.SectionName));
        services.AddSingleton<ICorpusManifestSource, FileCorpusManifestSource>();

        services.Configure<QdrantOptions>(configuration.GetSection(QdrantOptions.SectionName));
        services.AddSingleton<QdrantKnowledgeSearch>();
        services.AddSingleton<IKnowledgeSearch>(sp => sp.GetRequiredService<QdrantKnowledgeSearch>());

        // BGE-M3 over HTTP when a service URL is configured, and an embedder that throws when it
        // is not. Never a stub returning arbitrary vectors: that would ground the debate in
        // near-random chunks and report success. The exact-filter arm needs no embedder at all.
        services.Configure<EmbedderServiceOptions>(configuration.GetSection(EmbedderServiceOptions.SectionName));

        var embedder = configuration.GetSection(EmbedderServiceOptions.SectionName).Get<EmbedderServiceOptions>();

        if (embedder?.IsConfigured == true)
        {
            services.AddHttpClient<IQueryEmbedder, HttpQueryEmbedder>();
        }
        else
        {
            services.AddSingleton<IQueryEmbedder, NotConfiguredQueryEmbedder>();
        }

        // SEC-48: registered whether or not an embedding service exists. The manifest comparison
        // costs nothing and catches the mismatch that produces confident, meaningless results —
        // gating it on the optional half would skip it on most deployments.
        services.AddSingleton<CorpusBoundaryGuard>();
        services.AddHostedService<KnowledgeReadinessService>();

        services.AddScoped<Application.Features.Scan.Retrieval.KnowledgeRetrievalService>();

        // THE SWAP. Which retriever answers the pipeline is a configuration decision, not a code
        // one — the property the walking skeleton's seam was built to give us.
        //
        //   corpus configured -> SEC-22's decision tree, against the real corpus
        //   no corpus         -> the canned stub, which warns on every call
        //
        // The corpus alone is enough, and the embedder is genuinely optional. Looking up CWE-502
        // by its id is a payload filter with no vector in it, so an identifier-carrying finding
        // grounds for real whether or not a model exists. Without an embedder the meaning-based
        // arms report an honest miss per finding (see IQueryEmbedder.IsAvailable) rather than
        // returning canned text — so this is never the silent half-and-half it would be if the
        // fallback were the stub.
        var corpusReady = !string.IsNullOrWhiteSpace(configuration[$"{QdrantOptions.SectionName}:Endpoint"]);

        if (corpusReady)
        {
            services.AddScoped<IKnowledgeRetriever>(sp =>
                sp.GetRequiredService<Application.Features.Scan.Retrieval.KnowledgeRetrievalService>());
        }
        else
        {
            services.AddScoped<IKnowledgeRetriever, SeedKnowledgeRetriever>();
        }

        // ---- SEC-35: account deletion ----------------------------------------------------
        // Infrastructure, not Application: the delete order it enforces is a property of the
        // relational schema's Restrict foreign keys, which nothing above this layer knows about.
        services.AddScoped<ITenantPurge, TenantPurgeService>();

        // ---- SEC-46: scan-time orchestration (Pipeline B) --------------------------------
        // The claim is raw SQL Server (UPDATE ... OUTPUT) because handing one queued row to
        // exactly one worker is a property of the statement, not of the calling code. The
        // worker is always registered and decides at runtime whether to run, so the test host
        // and a scaled-out API instance can switch it off through configuration rather than by
        // rebuilding the container.
        services.Configure<ScanWorkerOptions>(configuration.GetSection(ScanWorkerOptions.SectionName));
        services.AddScoped<IScanJobClaim, SqlScanJobClaim>();

        // Starting a scan from the console (SEC-43 counterpart): the API asks the repository's own
        // CI to run the scan workflow, rather than cloning customer code and running scanners
        // itself. A typed HttpClient because it is one POST to api.github.com; the token is read
        // per call from IOptionsMonitor so a rotation needs no restart.
        services.Configure<GitHubDispatchOptions>(configuration.GetSection(GitHubDispatchOptions.SectionName));
        services.AddHttpClient<IScanDispatcher, GitHubScanDispatcher>(client =>
        {
            // GitHub rejects a request with no User-Agent outright.
            client.DefaultRequestHeaders.UserAgent.ParseAdd("SentinelAI");
            client.Timeout = TimeSpan.FromSeconds(30);
        });
        services.AddHostedService<ScanPipelineWorker>();

        services.AddScoped<IScanJobRepository, ScanJobRepository>();
        services.AddScoped(typeof(IGenericRepository<>), typeof(GenericRepository<>));
        services.AddScoped<IUnitOfWork, UnitOfWork>();

        // ---- Billing: subscriptions through Stripe Checkout -------------------------------
        // Vendor-neutral above this line: Application takes IBillingGateway and
        // IBillingEventReader, so the checkout, portal and webhook handlers are testable with a
        // fake and no Stripe account. StripeBillingGateway is the only class that calls Stripe.
        //
        // BillingSettings is a singleton read once at registration, the same shape EgressPolicy
        // uses: Infrastructure owns configuration, Application gets a settled answer. Registering
        // it unconditionally matters — a deployment with no Stripe account is a supported state,
        // and the endpoints answer 503 with an honest reason rather than failing to resolve.
        services.Configure<StripeOptions>(configuration.GetSection(StripeOptions.SectionName));
        services.AddSingleton(_ => BillingSettingsLoader.Load(configuration));
        services.AddScoped<IBillingGateway, StripeBillingGateway>();
        services.AddScoped<IBillingEventReader, StripeEventReader>();

        // The one place tenant isolation is stepped around for billing. See the interface for
        // why the webhook cannot run under the query filter and why this is safe.
        services.AddScoped<IBillingSubscriptionStore, BillingSubscriptionStore>();

        // What a plan grants, and the meter that enforces the part of it that is countable.
        // Scoped: both read per-request state and the counter writes.
        services.AddScoped<ITenantEntitlements, TenantEntitlements>();
        services.AddScoped<IScanQuotaCounter, ScanQuotaCounterStore>();

        // ---- Auth: login/register --------------------------------------------------------
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IPasswordHasher, PasswordHasher>();
        services.AddScoped<IJwtTokenIssuer, JwtTokenIssuer>();

        return services;
    }
}

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Infrastructure.Agents;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Graph;
using SentinelAI.Infrastructure.Knowledge;
using SentinelAI.Infrastructure.Implementation;
using SentinelAI.Infrastructure.Implementation.Repositories;
using SentinelAI.Infrastructure.Normalization;
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

        services.AddScoped<ICallerContext, HttpCallerContext>();
        services.AddScoped<ICorpusVersionProvider, ConfiguredCorpusVersionProvider>();
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
            services.AddHostedService<KnowledgeReadinessService>();
        }
        else
        {
            services.AddSingleton<IQueryEmbedder, NotConfiguredQueryEmbedder>();
        }

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

        services.AddScoped<IScanJobRepository, ScanJobRepository>();
        services.AddScoped(typeof(IGenericRepository<>), typeof(GenericRepository<>));
        services.AddScoped<IUnitOfWork, UnitOfWork>();

        // ---- Auth: login/register --------------------------------------------------------
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IPasswordHasher, PasswordHasher>();
        services.AddScoped<IJwtTokenIssuer, JwtTokenIssuer>();

        return services;
    }
}

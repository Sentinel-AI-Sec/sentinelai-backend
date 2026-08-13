using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Abstractions;
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

        // ---- SEC-45: knowledge retrieval -------------------------------------------------
        // A canned-answer stub so the walking skeleton can cross the retrieval seam before the
        // corpus exists. It logs a warning on every call. Replacing it with the Qdrant
        // retriever (SEC-09) is a change to this line and nothing upstream — which is the
        // property the thin slice was built to establish.
        services.AddScoped<IKnowledgeRetriever, SeedKnowledgeRetriever>();

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

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Infrastructure.Agents;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Implementation;
using SentinelAI.Infrastructure.Implementation.Repositories;
using SentinelAI.Infrastructure.Normalization;

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
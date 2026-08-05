using FluentValidation;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Common.Behaviors;
using SentinelAI.Application.Features.Auth;

namespace SentinelAI.Application;


public static class DependencyInjection
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(DependencyInjection).Assembly));
        services.AddValidatorsFromAssembly(typeof(DependencyInjection).Assembly);
        services.AddTransient(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));

        services.AddScoped<AuthTokenFactory>();

        // SEC-14: the Normalize stage. Its IFindingExtractor set is supplied by Infrastructure.
        services.AddScoped<Features.Scan.Normalization.NormalizationPipeline>();

        // SEC-15: the rule-mapping step inside that stage. Its IRuleMappingLookup is the SQL
        // implementation supplied by Infrastructure.
        services.AddScoped<Features.Scan.Normalization.RuleMappingResolver>();

        // SEC-16: the unify step that closes that stage. Pure — no port to supply.
        services.AddScoped<Features.Scan.Normalization.FindingUnifier>();

        return services;
    }
}
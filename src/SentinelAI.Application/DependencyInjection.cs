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

        return services;
    }
}
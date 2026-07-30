namespace SentinelAI.Api;

public static class DependencyInjection
{
    public static IServiceCollection AddApiServices(this IServiceCollection services)
    {
        services.AddControllers();

        return services;
    }

    public static WebApplication UseApiServices(this WebApplication app)
    {
        app.MapControllers();

        return app;
    }
}
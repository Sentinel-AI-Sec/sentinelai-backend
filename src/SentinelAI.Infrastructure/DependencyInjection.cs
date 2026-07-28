using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SentinelAI.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration config)
    {
        // var connectionString = config.GetConnectionString("Database");
        // services.AddDbContext<ApplicationDbContext>(options =>
        //     options.UseSqlServer(connectionString));
        // return services;

        return services;
    }
}
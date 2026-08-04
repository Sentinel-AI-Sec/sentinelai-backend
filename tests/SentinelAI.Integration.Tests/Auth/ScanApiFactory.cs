using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Integration.Tests.Auth;

/// <summary>
/// Boots the real <c>Program</c> — real auth middleware, real <c>[Authorize]</c>/
/// <c>[Authorize(Roles=...)]</c> enforcement, real EF tenant query filter — against an
/// isolated in-memory database instead of the shared SQL Server, with a fixed JWT signing
/// key so tests can mint their own tokens.
/// </summary>
public sealed class ScanApiFactory : WebApplicationFactory<Program>
{
    public const string JwtIssuer = "sentinelai-tests";
    public const string JwtAudience = "sentinelai-tests-audience";
    public const string JwtSigningKey = "test-only-signing-key-at-least-32-bytes-long!!";

    private readonly string _databaseName = Guid.NewGuid().ToString();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authentication:Jwt:Issuer"] = JwtIssuer,
                ["Authentication:Jwt:Audience"] = JwtAudience,
                ["Authentication:Jwt:SigningKey"] = JwtSigningKey,
            });
        });

        // ConfigureTestServices (not ConfigureServices) is what's guaranteed to run after
        // Program.cs's own AddInfrastructureServices — with a minimal-hosting entry point,
        // plain ConfigureServices can run before it, so the removal below would be undone
        // by the app's own UseSqlServer registration landing afterward.
        builder.ConfigureTestServices(services =>
        {
            // AddDbContext<T> registers more than DbContextOptions<T> and T themselves —
            // EF composes DbContextOptions<T> from every registered
            // IDbContextOptionsConfiguration<T>, so removing only those two leaves the
            // app's own UseSqlServer configuration in the container, and the resulting
            // options end up carrying both providers at once. Remove everything closed
            // over SentinelDbContext instead of guessing which service types matter.
            var toRemove = services
                .Where(d => d.ServiceType == typeof(SentinelDbContext)
                    || (d.ServiceType.IsGenericType
                        && d.ServiceType.GetGenericArguments().Contains(typeof(SentinelDbContext))))
                .ToList();
            foreach (var descriptor in toRemove) services.Remove(descriptor);

            services.AddDbContext<SentinelDbContext>(options => options.UseInMemoryDatabase(_databaseName));
        });
    }

    /// <summary>
    /// Seeds directly through a scoped <see cref="SentinelDbContext"/>. <c>Add</c>/
    /// <c>SaveChanges</c> bypass the tenant query filter — it only shapes reads — so this
    /// works regardless of which tenant (if any) the seeding context resolves to.
    /// </summary>
    public async Task SeedAsync(Action<SentinelDbContext> seed)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        seed(db);
        await db.SaveChangesAsync();
    }
}

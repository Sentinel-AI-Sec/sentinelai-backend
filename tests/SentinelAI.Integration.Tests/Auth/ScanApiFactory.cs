using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SentinelAI.Application.Abstractions;
using SentinelAI.Infrastructure.Agents.Providers;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Knowledge;

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

                // Pinned offline. The test host runs in the Development environment, so it
                // reads the developer's own appsettings.Development.json — and once that file
                // names a live provider, every test that reaches a debate starts making real
                // model calls with real credentials: slow, billable, non-deterministic, and
                // failing outright on a machine with no keys. The provider is a test-host
                // concern exactly like the database is, and is overridden here for the same
                // reason.
                ["SentinelAI:Models:Provider"] = "Scripted",
                ["SentinelAI:Models:ApiKey"] = "",
                ["SentinelAI:Models:Agents:Orchestrator:ApiKey"] = "",
                ["SentinelAI:Models:Agents:Red:ApiKey"] = "",
                ["SentinelAI:Models:Agents:Blue:ApiKey"] = "",
                ["SentinelAI:Models:Agents:Reporter:ApiKey"] = "",

                // Same argument, for the corpus. appsettings.json ships a non-empty
                // Knowledge:Endpoint (localhost:6334), which AddInfrastructureServices reads as
                // "a corpus is configured" and swaps SeedKnowledgeRetriever for the real
                // Qdrant-backed one — so every test that reaches a debate tried to open a gRPC
                // channel to a Qdrant nobody started.
                ["Knowledge:Endpoint"] = "",
                ["Knowledge:ApiKey"] = "",
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

            // Force the offline chat client, whatever configuration said.
            //
            // The configuration override above is not enough on its own: AddDebateServices
            // reads the model options *eagerly*, at registration time, so it has already
            // captured the developer's appsettings.Development.json before a test source is
            // merged in. Replacing the built factory here is what actually takes effect —
            // ConfigureTestServices is guaranteed to run after the app's own registrations.
            //
            // Without this, any test that reaches a debate makes real billable model calls on
            // a machine that happens to have keys configured, and times out on one that does
            // not. The provider is a test-host concern exactly like the database is.
            services.RemoveAll<IChatClientFactory>();
            services.AddSingleton<IChatClientFactory>(_ => new ChatClientFactory(new ModelProviderOptions()));

            // And the offline retriever, for the same reason the configuration override above
            // is not trusted on its own: AddInfrastructureServices decides which
            // IKnowledgeRetriever to register by reading Knowledge:Endpoint at registration
            // time, before a test configuration source is guaranteed to be in the builder.
            // Replacing the built registration is what actually takes effect.
            //
            // A live corpus is a genuine external dependency, and these tests are about the
            // API surface — the corpus itself is proven by LiveCorpusSmokeTests, which builds
            // its own container and skips when no corpus is reachable.
            services.RemoveAll<IKnowledgeRetriever>();
            services.AddScoped<IKnowledgeRetriever, SeedKnowledgeRetriever>();
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

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Providers;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Knowledge;

namespace SentinelAI.Integration.Tests.Auth;

/// <summary>
/// Boots the real <c>Program</c> — real auth middleware, real <c>[Authorize]</c>/
/// <c>[Authorize(Roles=...)]</c> enforcement, real EF tenant query filter — against an
/// isolated in-memory <b>SQLite</b> database instead of the shared SQL Server, with a fixed
/// JWT signing key so tests can mint their own tokens.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why SQLite and not <c>UseInMemoryDatabase</c> (audit 5-A).</b> The in-memory provider is
/// not a database. It enforces no unique index, no foreign key and no required-column rule, so
/// a model whose constraints are wrong passes every assertion here and then throws the first
/// time it meets SQL Server — which is the class of defect this suite exists to catch, not one
/// it should ship with. <c>AccountDeletionTests</c> already made this argument for the delete
/// ordering and moved to SQLite on its own; the reasoning was never specific to deletion, so
/// the whole API host now runs the same way.
/// </para>
/// <para>
/// <b>Why a shared-cache connection string rather than one open connection.</b> An in-memory
/// SQLite database lives exactly as long as a connection to it does, so something has to hold
/// one open — that is <see cref="_keepAlive"/>. Handing EF that <em>same</em>
/// <c>SqliteConnection</c> would funnel every request through a single, non-thread-safe object,
/// which a test host serving concurrent requests does genuinely hit. A named shared-cache
/// database lets each context open its own connection to the same store, the way a real
/// deployment does.
/// </para>
/// <para>
/// <b>The schema is created once, from the model</b> — see <see cref="CreateHost"/>.
/// <c>EnsureCreated</c> rather than <c>Migrate</c>: the migrations are SQL Server's and several
/// of them will not run on SQLite at all, and what these tests need is the model's constraints,
/// not its migration history. Whether the model and the migrations still agree is a different
/// question, and CI already has a job that asks it.
/// </para>
/// <para>
/// <b>What this deliberately does not soften.</b> SQLite is not SQL Server: it has no
/// <c>WITH (UPDLOCK, READPAST)</c>, so <c>SqlScanJobClaim</c> stays unexercised here (the
/// worker is switched off below for its own reasons anyway), and its type affinity is looser.
/// It does enforce the three things the in-memory provider dropped — uniqueness, foreign keys
/// and nullability — which is the whole reason for the change.
/// </para>
/// </remarks>
// Not sealed: BillingApiFactory extends this host with Stripe configuration and a fake gateway.
// Everything above — real auth middleware, real query filter, SQLite — is what it wants to reuse.
public class ScanApiFactory : WebApplicationFactory<Program>
{
    public const string JwtIssuer = "sentinelai-tests";
    public const string JwtAudience = "sentinelai-tests-audience";
    public const string JwtSigningKey = "test-only-signing-key-at-least-32-bytes-long!!";

    private readonly string _databaseName = Guid.NewGuid().ToString("N");

    /// <summary>
    /// Holds the in-memory database alive. Without a connection open somewhere, SQLite drops
    /// the store the moment the last one closes — which, with pooling, is between two requests.
    /// </summary>
    private SqliteConnection? _keepAlive;

    /// <summary>
    /// The connection string every context in this host opens. Named per factory instance, so
    /// two fixtures running side by side cannot see each other's rows.
    /// </summary>
    private string ConnectionString => $"DataSource=file:{_databaseName}?mode=memory&cache=shared";

    /// <summary>
    /// Where <c>FileSystemBundleStore</c> writes uploaded bundles for this host.
    /// </summary>
    /// <remarks>
    /// Overridden because the committed default is <c>/var/sentinelai/bundles</c>, which is not
    /// writable on a developer machine or a CI runner — so a test that actually uploads through
    /// <c>POST /v1/scans</c> would fail on the storage step for a reason that has nothing to do
    /// with ingest. Exposed rather than hidden so a test can assert the bytes really landed:
    /// "the row says it was stored" and "it was stored" are different claims.
    /// </remarks>
    public string BundleRoot { get; } =
        Path.Combine(Path.GetTempPath(), "sentinelai-tests", Guid.NewGuid().ToString("N"));

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

                // SEC-46's worker, off for the same class of reason as the two above — except
                // that here the damage is to the tests themselves rather than to a bill. Several
                // suites seed a scan job in Queued and then drive it by hand through
                // POST /v1/scans/{id}/graph; a worker running in the background would claim
                // those rows out from under them, at a moment that varies with machine load.
                // The claim is also raw SQL Server (WITH (UPDLOCK, READPAST)), which the SQLite
                // provider registered below cannot execute at all.
                ["Scanning:Worker:Enabled"] = "false",

                // See BundleRoot: the shipped default is an absolute Linux path no test
                // process can create.
                ["BundleStorage:RootPath"] = BundleRoot,
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

            services.AddDbContext<SentinelDbContext>(options => options.UseSqlite(ConnectionString));

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
    /// Builds the host, then opens the keep-alive connection and creates the schema on it.
    /// </summary>
    /// <remarks>
    /// Ordering matters in both directions. The keep-alive has to be open before any request
    /// runs, or the first context to close its connection takes the database with it; and the
    /// schema has to exist before the first request, because SQLite — unlike the in-memory
    /// provider — answers a query against a missing table with "no such table" rather than an
    /// empty set.
    /// </remarks>
    protected override IHost CreateHost(IHostBuilder builder)
    {
        var host = base.CreateHost(builder);

        _keepAlive = new SqliteConnection(ConnectionString);
        _keepAlive.Open();

        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        db.Database.EnsureCreated();

        return host;
    }

    /// <summary>
    /// Seeds directly through a scoped <see cref="SentinelDbContext"/>. <c>Add</c>/
    /// <c>SaveChanges</c> bypass the tenant query filter — it only shapes reads — so this
    /// works regardless of which tenant (if any) the seeding context resolves to.
    /// </summary>
    /// <remarks>
    /// The <c>Tenants</c> rows every seeded row's <c>TenantId</c> points at are filled in
    /// automatically — see <see cref="EnsureTenantsExist"/>.
    /// </remarks>
    public async Task SeedAsync(Action<SentinelDbContext> seed)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();

        seed(db);
        EnsureTenantsExist(db);

        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Adds a <see cref="Tenant"/> row for every tenant a seed referenced but did not create.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Under the in-memory provider a <c>Project</c> could carry a <c>TenantId</c> matching no
    /// row and nothing objected. On SQLite that is a foreign-key violation, correctly — but it
    /// is a violation about the <em>fixture</em>, not about the product, and no test here is
    /// about the existence of a tenant row. Filling it in once, here, is what keeps the enforced
    /// constraint from turning every seed in the suite into boilerplate that a new test will
    /// forget.
    /// </para>
    /// <para>
    /// Only the tenant is inferred, deliberately. Every other foreign key — a scan job's
    /// project, a chain hop's edge, a finding's job — is part of what the seed is describing,
    /// and a test whose graph does not join up should hear about it.
    /// </para>
    /// <para>
    /// Existing rows are left alone: a test that seeds its own tenant (to name it, or to assert
    /// on it) keeps the one it wrote.
    /// </para>
    /// </remarks>
    private static void EnsureTenantsExist(SentinelDbContext db)
    {
        var referenced = db.ChangeTracker.Entries<ITenantOwned>()
            .Where(e => e.State == EntityState.Added)
            .Select(e => e.Entity.TenantId)
            .Where(id => id != Guid.Empty)
            .Distinct()
            .ToList();

        if (referenced.Count == 0) return;

        // Tenant is not ITenantOwned, so it carries no query filter and this read sees every
        // row rather than only the ambient tenant's.
        var known = new HashSet<Guid>(db.Tenants.Select(t => t.Id));

        foreach (var tracked in db.ChangeTracker.Entries<Tenant>().Where(e => e.State == EntityState.Added))
            known.Add(tracked.Entity.Id);

        foreach (var tenantId in referenced.Where(id => !known.Contains(id)))
        {
            db.Tenants.Add(new Tenant
            {
                Id = tenantId,
                Name = $"seeded-{tenantId:N}",
                PlanTier = "test",
                CreatedAt = DateTime.UtcNow,
            });
        }
    }

    /// <summary>Drops the database along with the keep-alive connection holding it open.</summary>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing) return;

        _keepAlive?.Dispose();
        _keepAlive = null;

        // Disposing a pooled connection returns it to the pool rather than closing it, and a
        // pooled-but-open connection keeps alive a database this factory has finished with.
        // Clearing the pool is what actually releases it.
        SqliteConnection.ClearAllPools();

        // Best effort: a bundle left behind is litter in the temp directory, not a failure, and
        // throwing here would turn it into one after every assertion had already passed.
        try
        {
            if (Directory.Exists(BundleRoot)) Directory.Delete(BundleRoot, recursive: true);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}

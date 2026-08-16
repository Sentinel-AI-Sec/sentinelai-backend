using System.Reflection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Implementation.Repositories;
using SentinelAI.Integration.Tests.Scan;

namespace SentinelAI.Integration.Tests.Retention;

/// <summary>
/// SEC-35 account deletion: "delete my account" removes everything, permanently, and touches
/// nobody else's data.
/// </summary>
/// <remarks>
/// <para>
/// <b>These run on SQLite, not the in-memory provider every other test here uses</b>, and that
/// choice is the point. The delete order this feature implements exists solely to satisfy the
/// <c>Restrict</c> foreign keys on <c>ChainHop</c> and <c>GraphEdge</c> — and the in-memory
/// provider does not enforce foreign keys at all. Tested there, a wrong order passes every
/// assertion and then throws the first time it meets a real database, leaving an account half
/// deleted. SQLite enforces them, so the ordering is genuinely under test.
/// </para>
/// <para>
/// Deletion is irreversible here by design: nothing is soft-deleted, so the assertions are
/// simply that the rows are gone.
/// </para>
/// </remarks>
public sealed class AccountDeletionTests : IAsyncLifetime
{
    private SqliteConnection _connection = null!;
    private static readonly Guid Victim = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Bystander = Guid.Parse("22222222-2222-2222-2222-222222222222");

    public async Task InitializeAsync()
    {
        // Kept open for the lifetime of the test: an in-memory SQLite database exists only as
        // long as a connection to it does.
        _connection = new SqliteConnection("DataSource=:memory:");
        await _connection.OpenAsync();

        await using var db = NewContext();
        await db.Database.EnsureCreatedAsync();
    }

    public async Task DisposeAsync() => await _connection.DisposeAsync();

    private SentinelDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<SentinelDbContext>()
            .UseSqlite(_connection)
            .Options;

        // No ambient tenant: the purge must scope itself explicitly rather than inherit the
        // caller's context, which is what stops it deleting whatever the request happens to
        // point at.
        return new SentinelDbContext(options, new FakeCallerContext { TenantId = null });
    }

    private static TenantPurgeService PurgeFor(SentinelDbContext db, IBundleStore store) =>
        new(db, store, NullLogger<TenantPurgeService>.Instance);

    /// <summary>
    /// One row in every tenant-owned table, wired together the way a real scan leaves them —
    /// including the chain hops and graph edges whose Restrict keys make ordering matter.
    /// </summary>
    private async Task<Guid> SeedFullTenantAsync(Guid tenantId)
    {
        await using var db = NewContext();

        var tenant = new Tenant { Id = tenantId, Name = $"tenant-{tenantId:N}" };
        var user = new User
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId,
            Email = $"{tenantId:N}@example.test", PasswordHash = "hash", Role = Roles.Admin,
            CreatedAt = DateTime.UtcNow,
        };
        var refreshToken = new RefreshToken
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId, UserId = user.Id,
            // Unique per tenant: TokenHash carries a unique index, so two seeded tenants
            // sharing a literal would collide before the purge under test even ran.
            TokenHash = $"token-hash-{tenantId:N}", ExpiresAt = DateTime.UtcNow.AddDays(30),
            CreatedAt = DateTime.UtcNow,
        };
        var project = new Project
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId,
            RepoUrl = "https://example.test/repo", DefaultBranch = "main",
        };
        var job = new ScanJob
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId, ProjectId = project.Id,
            PrRef = "pr/1", CommitSha = "abc123", Status = ScanStatus.Completed,
            CorpusVersion = "v1", StartedAt = DateTime.UtcNow,
        };
        var bundle = new ScanBundle
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId, ScanJobId = job.Id,
            RunnerSecretScan = "clean", ArtifactManifest = "[]", ScannerVersions = "{}",
            ReceivedAt = DateTime.UtcNow, Sha256 = "sha", SizeBytes = 1, StorageLocator = "loc",
        };
        var finding = new Finding
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId, ScanJobId = job.Id,
            SourceTool = "checkov", Layer = Layer.Infra, Severity = 4,
            CweId = "CWE-284", NodeRef = "s3:bucket", Message = "public bucket",
        };
        var node = new GraphNode
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId, ScanJobId = job.Id,
            NodeKey = "s3:bucket", NodeType = NodeType.Resource, Layer = Layer.Infra,
        };
        var otherNode = new GraphNode
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId, ScanJobId = job.Id,
            NodeKey = "iam_role:api", NodeType = NodeType.IamRole, Layer = Layer.Infra,
        };
        var edge = new GraphEdge
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId, ScanJobId = job.Id,
            FromNodeId = otherNode.Id, ToNodeId = node.Id,
            Relation = "can-access", Confidence = Confidence.Certain,
        };
        var chain = new Chain
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId, ScanJobId = job.Id,
            Status = ChainStatus.Candidate, MinConfidence = Confidence.Certain,
        };
        var hop = new ChainHop
        {
            // Both Restrict-keyed references populated on purpose: FindingId and EdgeId are the
            // two foreign keys that make delete order matter at all.
            Id = Guid.CreateVersion7(), TenantId = tenantId, ChainId = chain.Id,
            FindingId = finding.Id, EdgeId = edge.Id, HopOrder = 1, TechniqueId = "T1078",
        };
        var report = new Report
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId, ScanJobId = job.Id,
            Summary = "draft", Framing = "draft_audit", Retained = true, CreatedAt = DateTime.UtcNow,
        };
        var citation = new Citation
        {
            Id = Guid.CreateVersion7(), TenantId = tenantId, ReportId = report.Id,
            KnowledgeId = "CWE-284", Source = "OWASP", Collection = "offense",
        };

        db.Tenants.Add(tenant);
        db.Users.Add(user);
        db.RefreshTokens.Add(refreshToken);
        db.Projects.Add(project);
        db.ScanJobs.Add(job);
        db.ScanBundles.Add(bundle);
        db.Findings.Add(finding);
        db.GraphNodes.AddRange(node, otherNode);
        db.GraphEdges.Add(edge);
        db.Chains.Add(chain);
        db.ChainHops.Add(hop);
        db.Reports.Add(report);
        db.Citations.Add(citation);

        await db.SaveChangesAsync();
        return job.Id;
    }

    [Fact]
    public async Task Deleting_an_account_removes_every_row_it_owned()
    {
        await SeedFullTenantAsync(Victim);

        await using (var db = NewContext())
            await PurgeFor(db, new RecordingBundleStore()).PurgeAsync(Victim);

        await using var check = NewContext();

        // Reflection over the model rather than a hand-written list of tables. A hand-written
        // list is correct on the day it is written and silently wrong the day someone adds a
        // table and forgets this method — and a table that survives account deletion forever
        // is precisely the failure this feature exists to prevent.
        foreach (var entityType in check.Model.GetEntityTypes()
                     .Where(e => typeof(ITenantOwned).IsAssignableFrom(e.ClrType)))
        {
            var remaining = await CountForTenantAsync(check, entityType.ClrType, Victim);

            Assert.True(remaining == 0,
                $"{entityType.ClrType.Name} still has {remaining} row(s) after account deletion. "
                + "If this type is new, add it to TenantPurgeService in dependency order.");
        }

        Assert.Null(await check.Tenants.IgnoreQueryFilters().FirstOrDefaultAsync(t => t.Id == Victim));
    }

    [Fact]
    public async Task Another_tenants_data_is_untouched()
    {
        await SeedFullTenantAsync(Victim);
        await SeedFullTenantAsync(Bystander);

        await using (var db = NewContext())
            await PurgeFor(db, new RecordingBundleStore()).PurgeAsync(Victim);

        await using var check = NewContext();

        foreach (var entityType in check.Model.GetEntityTypes()
                     .Where(e => typeof(ITenantOwned).IsAssignableFrom(e.ClrType)))
        {
            var remaining = await CountForTenantAsync(check, entityType.ClrType, Bystander);
            Assert.True(remaining > 0, $"{entityType.ClrType.Name} lost the bystander tenant's row.");
        }

        Assert.NotNull(await check.Tenants.IgnoreQueryFilters().FirstOrDefaultAsync(t => t.Id == Bystander));
    }

    [Fact]
    public async Task Stored_bundles_are_purged_from_storage_not_only_from_the_database()
    {
        // The rows say which bundles exist. Delete them first and the files are orphaned on
        // disk with nothing left pointing at them — deleted from the record, undeletable forever.
        var jobId = await SeedFullTenantAsync(Victim);
        var store = new RecordingBundleStore();

        await using (var db = NewContext())
            await PurgeFor(db, store).PurgeAsync(Victim);

        Assert.Contains(jobId, store.Purged);
    }

    [Fact]
    public async Task The_receipt_counts_what_was_destroyed()
    {
        await SeedFullTenantAsync(Victim);

        await using var db = NewContext();
        var report = await PurgeFor(db, new RecordingBundleStore()).PurgeAsync(Victim);

        Assert.Equal(1, report.BundlesPurged);
        Assert.True(report.TotalRows >= 13, $"expected every seeded row counted, got {report.TotalRows}");
        Assert.Equal(1, report.Rows[nameof(Tenant)]);
        Assert.Equal(1, report.Rows[nameof(ChainHop)]);
        Assert.Equal(1, report.Rows[nameof(GraphEdge)]);
    }

    [Fact]
    public async Task Deleting_an_account_that_has_nothing_is_not_an_error()
    {
        await using var db = NewContext();

        var report = await PurgeFor(db, new RecordingBundleStore()).PurgeAsync(Guid.NewGuid());

        Assert.Equal(0, report.TotalRows);
        Assert.Equal(0, report.BundlesPurged);
    }

    [Fact]
    public async Task An_empty_tenant_id_is_refused()
    {
        await using var db = NewContext();

        await Assert.ThrowsAsync<ArgumentException>(
            () => PurgeFor(db, new RecordingBundleStore()).PurgeAsync(Guid.Empty));
    }

    private static async Task<int> CountForTenantAsync(SentinelDbContext db, Type clrType, Guid tenantId)
    {
        // db.Set<T>() by reflection, since the entity type is only known at runtime here.
        var set = typeof(DbContext)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Single(m => m.Name == nameof(DbContext.Set) && m.IsGenericMethod && m.GetParameters().Length == 0)
            .MakeGenericMethod(clrType)
            .Invoke(db, null)!;

        // Selected by parameter count: IgnoreQueryFilters has an overload taking filter keys,
        // so asking for it by name alone is ambiguous.
        var ignoreQueryFilters = typeof(EntityFrameworkQueryableExtensions)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Single(m => m.Name == nameof(EntityFrameworkQueryableExtensions.IgnoreQueryFilters)
                         && m.GetParameters().Length == 1);

        var query = (IQueryable<ITenantOwned>)ignoreQueryFilters
            .MakeGenericMethod(clrType)
            .Invoke(null, [set])!;

        return await query.Where(e => e.TenantId == tenantId).CountAsync();
    }

    /// <summary>A bundle store that only remembers what it was told to delete.</summary>
    private sealed class RecordingBundleStore : IBundleStore
    {
        public List<Guid> Purged { get; } = [];

        public Task PurgeAsync(Guid scanJobId, CancellationToken ct)
        {
            Purged.Add(scanJobId);
            return Task.CompletedTask;
        }

        public Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct) =>
            throw new NotSupportedException();

        public Task<IReadOnlyList<StoredBundleFile>> OpenFindingsAsync(string locator, CancellationToken ct) =>
            throw new NotSupportedException();

        public Task<IReadOnlyList<StoredBundleFile>> OpenGraphInputsAsync(string locator, CancellationToken ct) =>
            throw new NotSupportedException();
    }
}

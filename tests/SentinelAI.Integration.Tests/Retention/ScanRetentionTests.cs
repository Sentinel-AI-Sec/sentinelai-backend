using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Retention;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Implementation;
using SentinelAI.Infrastructure.Implementation.Repositories;
using SentinelAI.Integration.Tests.Scan;

namespace SentinelAI.Integration.Tests.Retention;

/// <summary>
/// SEC-35's two default-to-delete rules: the received bundle always goes, and the report is
/// kept only if the submitter opted in.
/// </summary>
/// <remarks>
/// Every one of these asserts on state <em>after</em> the policy ran — the bundle actually left
/// the store, the row actually says purged, the report row actually is or is not there. Before
/// this task all three facts had a field describing them and nothing setting it, which is the
/// failure mode worth testing against: a promise that reads as kept.
/// </remarks>
public sealed class ScanRetentionTests
{
    private static readonly Guid Tenant = Guid.Parse("33333333-3333-3333-3333-333333333333");

    private static SentinelDbContext NewContext(string name) =>
        new(new DbContextOptionsBuilder<SentinelDbContext>().UseInMemoryDatabase(name).Options,
            new FakeCallerContext { TenantId = Tenant });

    private static async Task<(SentinelDbContext Db, Guid JobId)> SeedJobAsync(string name, bool retainReport)
    {
        var db = NewContext(name);

        // A project is required, not decoration: ScanJobRepository scopes by
        // `job.Project.TenantId`, so a job without one is invisible to the lookup the policy
        // makes and retention would refuse a job that really is the caller's.
        var project = new Project
        {
            Id = Guid.CreateVersion7(),
            TenantId = Tenant,
            RepoUrl = "https://example.test/repo",
            DefaultBranch = "main",
        };
        db.Projects.Add(project);

        var job = new ScanJob
        {
            Id = Guid.CreateVersion7(),
            TenantId = Tenant,
            ProjectId = project.Id,
            PrRef = "pr/1",
            CommitSha = "abc123",
            Status = ScanStatus.Completed,
            CorpusVersion = "v1",
            StartedAt = DateTime.UtcNow,
            BundlePurged = false,
            RetainReport = retainReport,
        };

        db.ScanJobs.Add(job);
        await db.SaveChangesAsync();

        return (db, job.Id);
    }

    private static Report NewReport(Guid jobId) => new()
    {
        Id = Guid.CreateVersion7(),
        TenantId = Tenant,
        ScanJobId = jobId,
        Summary = "draft audit",
        Framing = "draft_audit",
        Retained = false,
        CreatedAt = DateTime.UtcNow,
    };

    private static ScanRetentionPolicy PolicyFor(SentinelDbContext db, IBundleStore store) =>
        new(new UnitOfWork(db, new ScanJobRepository(db), new UserRepository(db), new RefreshTokenRepository(db)),
            store,
            NullLogger<ScanRetentionPolicy>.Instance);

    [Fact]
    public async Task The_bundle_is_deleted_and_the_job_records_it()
    {
        var (db, jobId) = await SeedJobAsync(nameof(The_bundle_is_deleted_and_the_job_records_it), retainReport: false);
        await using var _ = db;
        var store = new RecordingBundleStore();

        var outcome = await PolicyFor(db, store).ApplyAfterAuditAsync(Tenant, jobId, NewReport(jobId));

        Assert.True(outcome.BundlePurged);
        Assert.Contains(jobId, store.Purged);

        // Both halves matter: the store was told, and the row says so. A flag set without the
        // deletion is a lie; a deletion without the flag gets purged again forever.
        var job = await db.ScanJobs.AsNoTracking().SingleAsync(j => j.Id == jobId);
        Assert.True(job.BundlePurged);
    }

    [Fact]
    public async Task The_bundle_goes_even_when_the_report_is_retained()
    {
        // The two rules are independent. Opting into report retention is not opting into
        // keeping the uploaded bundle — that is the customer's own infrastructure material.
        var (db, jobId) = await SeedJobAsync(nameof(The_bundle_goes_even_when_the_report_is_retained), retainReport: true);
        await using var _ = db;
        var store = new RecordingBundleStore();

        var outcome = await PolicyFor(db, store).ApplyAfterAuditAsync(Tenant, jobId, NewReport(jobId));

        Assert.True(outcome.BundlePurged);
        Assert.True(outcome.ReportRetained);
        Assert.Contains(jobId, store.Purged);
    }

    [Fact]
    public async Task A_report_nobody_opted_into_is_never_written_down()
    {
        var (db, jobId) = await SeedJobAsync(nameof(A_report_nobody_opted_into_is_never_written_down), retainReport: false);
        await using var _ = db;

        var report = NewReport(jobId);
        var outcome = await PolicyFor(db, new RecordingBundleStore()).ApplyAfterAuditAsync(Tenant, jobId, report);

        Assert.False(outcome.ReportRetained);
        Assert.False(report.Retained);
        Assert.Empty(await db.Reports.AsNoTracking().Where(r => r.ScanJobId == jobId).ToListAsync());
    }

    [Fact]
    public async Task A_report_the_submitter_asked_for_is_kept()
    {
        var (db, jobId) = await SeedJobAsync(nameof(A_report_the_submitter_asked_for_is_kept), retainReport: true);
        await using var _ = db;

        var report = NewReport(jobId);
        var outcome = await PolicyFor(db, new RecordingBundleStore()).ApplyAfterAuditAsync(Tenant, jobId, report);

        Assert.True(outcome.ReportRetained);
        Assert.True(report.Retained);

        var stored = Assert.Single(await db.Reports.AsNoTracking().Where(r => r.ScanJobId == jobId).ToListAsync());
        Assert.True(stored.Retained);
    }

    [Fact]
    public async Task The_opt_in_comes_from_the_scan_job_not_from_the_report_builder()
    {
        // The regression this task fixed: ReportBuilder hardcodes Retained = false because it
        // cannot know the answer, and metadata.retain_report lands on the ScanJob. Nothing
        // joined the two, so the submitter's choice was captured and then ignored.
        var (db, jobId) = await SeedJobAsync(nameof(The_opt_in_comes_from_the_scan_job_not_from_the_report_builder), retainReport: true);
        await using var _ = db;

        var report = NewReport(jobId);
        Assert.False(report.Retained);   // as the builder leaves it

        await PolicyFor(db, new RecordingBundleStore()).ApplyAfterAuditAsync(Tenant, jobId, report);

        Assert.True(report.Retained);    // as the submitter asked for
    }

    [Fact]
    public async Task Withdrawing_consent_removes_a_report_stored_by_an_earlier_run()
    {
        // "Not retained" has to mean nothing is on disk, not merely that this run declined to
        // add a row. Otherwise a job that once opted in keeps its old report forever.
        var (db, jobId) = await SeedJobAsync(nameof(Withdrawing_consent_removes_a_report_stored_by_an_earlier_run), retainReport: false);
        await using var _ = db;

        var earlier = NewReport(jobId);
        earlier.Retained = true;
        earlier.Citations.Add(new Citation
        {
            Id = Guid.CreateVersion7(), TenantId = Tenant, ReportId = earlier.Id,
            KnowledgeId = "CWE-284", Source = "OWASP", Collection = "offense",
        });
        db.Reports.Add(earlier);
        await db.SaveChangesAsync();

        await PolicyFor(db, new RecordingBundleStore()).ApplyAfterAuditAsync(Tenant, jobId, NewReport(jobId));

        Assert.Empty(await db.Reports.AsNoTracking().Where(r => r.ScanJobId == jobId).ToListAsync());

        // Citations go with it. Left behind they are orphaned rows quoting a report that no
        // longer exists — data we said we deleted, still there under another table's name.
        Assert.Empty(await db.Citations.AsNoTracking().Where(c => c.ReportId == earlier.Id).ToListAsync());
    }

    [Fact]
    public async Task Applying_retention_twice_is_harmless()
    {
        // A retried job, or a worker that crashed after purging but before committing, must
        // not fail the second time round.
        var (db, jobId) = await SeedJobAsync(nameof(Applying_retention_twice_is_harmless), retainReport: false);
        await using var _ = db;
        var store = new RecordingBundleStore();
        var policy = PolicyFor(db, store);

        await policy.ApplyAfterAuditAsync(Tenant, jobId, NewReport(jobId));
        var second = await policy.ApplyAfterAuditAsync(Tenant, jobId, NewReport(jobId));

        Assert.True(second.BundlePurged);
        Assert.Equal(2, store.Purged.Count(id => id == jobId));
    }

    [Fact]
    public async Task Retention_for_a_job_of_another_tenant_is_refused()
    {
        // The job exists, but not for this caller. Silently doing nothing would report a
        // successful purge that never happened.
        var (db, jobId) = await SeedJobAsync(nameof(Retention_for_a_job_of_another_tenant_is_refused), retainReport: false);
        await using var _ = db;

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => PolicyFor(db, new RecordingBundleStore())
                .ApplyAfterAuditAsync(Guid.NewGuid(), jobId, NewReport(jobId)));
    }

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

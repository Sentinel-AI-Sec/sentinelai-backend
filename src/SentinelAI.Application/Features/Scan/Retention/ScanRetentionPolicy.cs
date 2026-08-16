using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Retention;

/// <summary>
/// The default retention policy (SEC-35): delete the bundle, keep the report only on opt-in.
/// </summary>
/// <remarks>
/// <para>
/// Before this existed, every piece of the promise was present except the part that acts.
/// <c>ScanJob.BundlePurged</c> was a column only the manual <c>DELETE</c> endpoint ever set, so a
/// bundle nobody remembered to purge stayed on disk forever. <c>ScanJob.RetainReport</c> was read
/// out of <c>metadata.retain_report</c> at ingest and then never looked at again, and
/// <c>Report.Retained</c> was hardcoded to <c>false</c> by the builder — so a submitter who asked
/// us not to keep their report got a field that agreed with them and a system that ignored it.
/// A promise with a flag and no behaviour is worse than no promise: it reads as kept.
/// </para>
/// <para>
/// The bundle is purged from storage <em>before</em> the row is updated. If the order were
/// reversed and the save failed, the database would claim a purge that never happened, and
/// nothing would ever try again — the flag is what stops a retry. Purging first can at worst
/// delete the bundle and fail to record it, which the next call simply repeats: the store's
/// purge is idempotent by contract.
/// </para>
/// </remarks>
public sealed class ScanRetentionPolicy(
    IUnitOfWork unitOfWork,
    IBundleStore bundleStore,
    ILogger<ScanRetentionPolicy> logger) : IScanRetentionPolicy
{
    public async Task<RetentionOutcome> ApplyAfterAuditAsync(
        Guid tenantId, Guid scanJobId, Report report, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(report);

        var job = await unitOfWork.ScanJobRepository.GetForTenantAsync(scanJobId, tenantId, ct)
            ?? throw new InvalidOperationException(
                $"Cannot apply retention: no scan job '{scanJobId}' for tenant '{tenantId}'. "
                + "The audit that produced this report ran against a job that no longer exists.");

        // ---- Rule 1: the bundle goes, always ---------------------------------------------
        await bundleStore.PurgeAsync(scanJobId, ct);

        // Flagged on the tracked instance, not on the one the repository handed back. That
        // one is AsNoTracking, and attaching it throws outright if this scope has already
        // loaded the same job — which an earlier pipeline stage generally has. Reading through
        // the tracked set instead lets EF's identity resolution return whatever instance is
        // already in the change tracker.
        var tracked = await unitOfWork.Repository<ScanJob>()
            .GetTableAsTracked()
            .FirstOrDefaultAsync(j => j.Id == scanJobId, ct);

        if (tracked is not null)
        {
            tracked.BundlePurged = true;
        }
        else
        {
            job.BundlePurged = true;
            await unitOfWork.Repository<ScanJob>().UpdateAsync(job);
        }

        // ---- Rule 2: the report stays only if it was asked for ---------------------------
        report.Retained = job.RetainReport;

        if (report.Retained)
        {
            await unitOfWork.Repository<Report>().AddAsync(report);
        }
        else
        {
            // A report from an earlier run of the same job may already be stored — for
            // instance if the submitter opted in, then re-ran having changed their mind.
            // "Not retained" has to mean nothing is on disk, not merely that this run
            // declined to add a row.
            await DropStoredReportsAsync(scanJobId, ct);
        }

        await unitOfWork.CompleteAsync();

        logger.LogInformation(
            "Retention for job {JobId}: bundle purged; report {Fate} (submitter opt-in: {OptIn})",
            scanJobId, report.Retained ? "retained" : "discarded", job.RetainReport);

        return new RetentionOutcome(BundlePurged: true, ReportRetained: report.Retained);
    }

    /// <summary>
    /// Removes any stored report for this job, citations first.
    /// </summary>
    /// <remarks>
    /// Citations are deleted explicitly rather than left to the cascade. The relational cascade
    /// would handle it, but the in-memory provider the tests run on does not enforce one — so
    /// relying on it would mean the tests prove a deletion the database performs and the test
    /// double does not, which is the wrong way round for a promise about deleted data.
    /// </remarks>
    private async Task DropStoredReportsAsync(Guid scanJobId, CancellationToken ct)
    {
        var stored = await unitOfWork.Repository<Report>()
            .GetTableAsTracked()
            .Where(r => r.ScanJobId == scanJobId)
            .Include(r => r.Citations)
            .ToListAsync(ct);

        if (stored.Count == 0) return;

        foreach (var report in stored)
        {
            if (report.Citations.Count > 0)
                await unitOfWork.Repository<Citation>().DeleteRangeAsync([.. report.Citations]);
        }

        await unitOfWork.Repository<Report>().DeleteRangeAsync(stored);

        logger.LogInformation(
            "Removed {Count} previously stored report(s) for job {JobId}: retention was not opted into",
            stored.Count, scanJobId);
    }
}

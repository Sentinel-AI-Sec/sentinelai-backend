using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Features.Scan.Orchestration;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Implementation.Repositories;

namespace SentinelAI.Infrastructure.Orchestration;

/// <summary>
/// Drives queued scan jobs through Pipeline B without anybody calling anything by hand (SEC-46).
/// </summary>
/// <remarks>
/// <para>
/// <b>In-process, not an external queue.</b> A scan job's work queue is one table this service
/// already owns transactionally, and <see cref="IScanJobClaim"/> makes handing a row to exactly
/// one worker a property of the database rather than of a broker. Adding a broker would add a
/// second thing that can be down, a second delivery guarantee to reason about, and a second copy
/// of the job's state to keep in step with <c>scan_jobs</c> — for a workload measured in scans
/// per hour. If this ever needs to fan out across machines it can: the claim is already safe
/// against concurrent workers, so a second process is a deployment change and not a rewrite.
/// </para>
/// <para>
/// <b>Two scopes per job, on purpose.</b> The claim runs in its own short-lived scope because at
/// that moment the worker does not yet know whose job it is — the scope's <c>DbContext</c> is
/// filtered to <c>Guid.Empty</c> and can see no tenant-owned row. That is harmless for the claim,
/// which is raw SQL and bypasses query filters, and unusable for everything after it. So the run
/// gets a second scope whose very first act is to assume the claimed tenant, before any
/// <c>DbContext</c> in it is constructed. See <see cref="AssumableCallerContext"/>.
/// </para>
/// <para>
/// <b>The loop never dies.</b> Every failure is caught and logged and the loop continues. A
/// background service whose <c>ExecuteAsync</c> throws is stopped for the lifetime of the
/// process, so one malformed job would silently end all scanning until someone restarted the
/// host — which is a worse outcome than any single failed scan.
/// </para>
/// </remarks>
public sealed class ScanPipelineWorker(
    IServiceScopeFactory scopeFactory,
    IOptions<ScanWorkerOptions> options,
    ILogger<ScanPipelineWorker> logger) : BackgroundService
{
    private readonly ScanWorkerOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            // Said out loud rather than returning quietly: "queued scans never start" is
            // otherwise indistinguishable from a broken pipeline, and this is the first thing
            // anyone should find when they go looking.
            logger.LogInformation(
                "Scan pipeline worker is disabled ({Section}:Enabled = false); queued scan jobs "
                + "will not be picked up by this process", ScanWorkerOptions.SectionName);

            return;
        }

        logger.LogInformation(
            "Scan pipeline worker started; polling every {PollInterval}", _options.PollInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            ClaimedScanJob? claimed;

            try
            {
                claimed = await ClaimNextAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // Typically the database being unreachable. Back off for a poll interval rather
                // than hammering it, and keep the loop alive so the worker recovers on its own
                // when the database does.
                logger.LogError(ex, "Could not claim a scan job; retrying in {PollInterval}", _options.PollInterval);
                await DelayAsync(stoppingToken);
                continue;
            }

            if (claimed is null)
            {
                // An empty queue is the ordinary state, so this is Debug — at Information it
                // would bury every real event under a heartbeat.
                logger.LogDebug("No queued scan job to claim; waiting {PollInterval}", _options.PollInterval);
                await DelayAsync(stoppingToken);
                continue;
            }

            logger.LogInformation(
                "Claimed scan job {ScanJobId} for tenant {TenantId}", claimed.ScanJobId, claimed.TenantId);

            await RunAsync(claimed, stoppingToken);

            // Deliberately no delay here. The poll interval is the cost of asking an empty queue
            // again; a claim that succeeded is evidence there may be more, so a backlog drains at
            // the speed of the pipeline rather than one job per interval.
        }

        logger.LogInformation("Scan pipeline worker stopping");
    }

    /// <summary>
    /// Runs one claimed job to completion, in a scope that has assumed its tenant.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Assume comes first, before anything else is resolved.</b> <c>SentinelDbContext</c> reads
    /// the tenant in its constructor, so a context built before the assumption would carry
    /// <c>Guid.Empty</c> for the rest of the scope and quietly return no rows. Resolving the
    /// runner first would construct one through its dependency chain, which is why these two
    /// lines are in this order and not the other.
    /// </para>
    /// <para>
    /// <b>The runner reports failure rather than throwing it</b> — a failed scan is an outcome,
    /// not an exception. So anything caught here is the runner itself breaking, and the job it
    /// was given is still <c>Running</c> with nothing left to advance it. The claim matches only
    /// <c>Queued</c> rows, so nothing will ever pick it up again; recording the failure is what
    /// keeps a bug from turning into a permanently invisible job.
    /// </para>
    /// </remarks>
    private async Task RunAsync(ClaimedScanJob claimed, CancellationToken ct)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();

            scope.ServiceProvider.GetRequiredService<AssumableCallerContext>().Assume(claimed.TenantId);

            var runner = scope.ServiceProvider.GetRequiredService<ScanPipelineRunner>();
            var outcome = await runner.RunAsync(claimed.ScanJobId, claimed.TenantId, ct);

            if (outcome.Succeeded)
            {
                logger.LogInformation(
                    "Scan job {ScanJobId} completed: {Findings} finding(s), {Chains} candidate chain(s)",
                    outcome.ScanJobId, outcome.Findings, outcome.CandidateChains);
            }
            else
            {
                // Warning and not Error: the pipeline did its job by attributing and recording
                // this. The runner has already logged the exception itself at Error with a stack.
                logger.LogWarning(
                    "Scan job {ScanJobId} failed at stage {Stage}: {Reason}",
                    outcome.ScanJobId, outcome.FailedStage, outcome.FailureReason);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex, "The pipeline runner threw for scan job {ScanJobId}; marking it failed so it "
                + "is not left Running with nothing to advance it", claimed.ScanJobId);

            await MarkStrandedAsync(claimed, ex);
        }
    }

    /// <summary>
    /// Last resort: writes <c>Failed</c> onto a job whose run died outside the runner's own
    /// error handling.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A scope of its own, because the one that just threw may hold a <c>DbContext</c> with a
    /// failed transaction or a broken connection — the most likely reason to be here at all.
    /// </para>
    /// <para>
    /// <c>CancellationToken.None</c>, because the common path into this method is the host
    /// stopping mid-run, and passing the token that just cancelled would cancel the write meant
    /// to clean up after it. The work is one small update and cannot meaningfully delay shutdown.
    /// A job interrupted by a shutdown genuinely did not finish, and <c>Failed</c> is visible and
    /// resubmittable where <c>Running</c> is neither.
    /// </para>
    /// </remarks>
    private async Task MarkStrandedAsync(ClaimedScanJob claimed, Exception failure)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();

            scope.ServiceProvider.GetRequiredService<AssumableCallerContext>().Assume(claimed.TenantId);

            var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

            var job = await unitOfWork.Repository<ScanJob>()
                .GetTableAsTracked()
                .FirstOrDefaultAsync(j => j.Id == claimed.ScanJobId, CancellationToken.None);

            if (job is null)
            {
                logger.LogError(
                    "Could not re-read scan job {ScanJobId} to mark it failed; it remains Running",
                    claimed.ScanJobId);

                return;
            }

            job.Status = ScanStatus.Failed;
            job.CompletedAt = DateTime.UtcNow;
            job.FailureReason = $"the scan worker did not finish this job: {failure.Message}";

            await unitOfWork.CompleteAsync();
        }
        catch (Exception ex)
        {
            // Nothing further to try. Logged loudly because the job is now stuck in Running and
            // only an operator can tell it apart from one that is legitimately still going.
            logger.LogError(
                ex, "Could not mark scan job {ScanJobId} as failed; it is stranded in Running",
                claimed.ScanJobId);
        }
    }

    /// <summary>
    /// One claim attempt, in a scope of its own.
    /// </summary>
    /// <remarks>
    /// The scope is disposed immediately. Its <c>DbContext</c> has no tenant and therefore cannot
    /// usefully read anything else, so keeping it alive for the run would be keeping the one
    /// context guaranteed to return empty results for the work that follows.
    /// </remarks>
    private async Task<ClaimedScanJob?> ClaimNextAsync(CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        var claim = scope.ServiceProvider.GetRequiredService<IScanJobClaim>();

        return await claim.ClaimNextAsync(ct);
    }

    /// <summary>Waits out a poll interval, treating shutdown as an ordinary exit rather than an error.</summary>
    private async Task DelayAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(_options.PollInterval, ct);
        }
        catch (OperationCanceledException)
        {
            // The host is stopping. The loop's own condition ends the run.
        }
    }
}

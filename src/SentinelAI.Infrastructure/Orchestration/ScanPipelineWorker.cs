using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentinelAI.Domain.Abstractions.Repositories;
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

            // TODO(SEC-46 checkpoint b): dispatch to ScanPipelineRunner in a scope that has
            // assumed claimed.TenantId. Until that lands, Scanning:Worker:Enabled ships false so
            // this loop cannot strand a claimed job in Running.
        }

        logger.LogInformation("Scan pipeline worker stopping");
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

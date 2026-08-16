using System.Net;
using System.Text.Json.Serialization;
using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.ThinSlice;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Commands.RunAudit;

/// <summary>
/// Retrieve (SEC-21/22) → debate (SEC-26/27) → report (SEC-45) → retention (SEC-35), for one job.
/// </summary>
public sealed class RunAuditStageCommandHandler(
    IUnitOfWork unitOfWork,
    ICallerContext caller,
    ThinSlicePipeline pipeline,
    ChainOutcomeWriter chainOutcomeWriter,
    ILogger<RunAuditStageCommandHandler> logger)
    : IRequestHandler<RunAuditStageCommand, Response>
{
    public async Task<Response> Handle(RunAuditStageCommand request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        // It writes a report and purges the bundle, so it is a write like the graph stage is.
        if (!caller.HasScope(AuthScopes.ScanWrite))
            return await Response.FailureAsync($"the '{AuthScopes.ScanWrite}' scope is required", HttpStatusCode.Forbidden);

        var tenantId = caller.TenantId.Value;

        var job = await unitOfWork.ScanJobRepository.GetForTenantAsync(request.ScanJobId, tenantId, ct);
        if (job is null)
            return await Response.FailureAsync($"no scan job '{request.ScanJobId}'", HttpStatusCode.NotFound);

        // The graph stage's output, read back rather than rebuilt.
        var findings = await unitOfWork.Repository<Finding>()
            .GetTableAsNotTracked()
            .Where(f => f.ScanJobId == job.Id)
            .ToListAsync(ct);

        if (findings.Count == 0)
        {
            return await Response.FailureAsync(
                "this job has no normalized findings — run the graph stage first",
                HttpStatusCode.Conflict);
        }

        var nodes = await unitOfWork.Repository<GraphNode>()
            .GetTableAsNotTracked()
            .Where(n => n.ScanJobId == job.Id)
            .ToListAsync(ct);

        // The graph stage's edges, read back alongside its nodes. Without these Red has no real
        // hop to assert — the resource graph in the brief would say "no edges were extracted"
        // even when SEC-17-20 built a real one, and the debate would run over nothing (SEC-26).
        var edges = await unitOfWork.Repository<GraphEdge>()
            .GetTableAsNotTracked()
            .Where(e => e.ScanJobId == job.Id)
            .ToListAsync(ct);

        try
        {
            // Candidate chains are left null: the persisted Chain rows are the graph stage's
            // own record, and rebuilding CandidateChain objects from them here would duplicate
            // SEC-20's traversal with no new information. The debate reasons over the graph.
            var result = await pipeline.RunAsync(findings, tenantId, job.Id, nodes, edges, candidates: null, ct);

            // SEC-28: the graph stage's own chain row otherwise stays "candidate" forever — a
            // reader of the chains endpoint could never tell a chain the debate validated from
            // one nobody has looked at yet.
            await chainOutcomeWriter.ApplyAsync(job.Id, result.Audit, ct);

            await AdvanceStageAsync(job, ScanStage.Report, failure: null);

            return await Response.SuccessAsync(
                new RunAuditStageResponse
                {
                    ScanJobId = job.Id.ToString(),
                    // Null when retention discarded it — which is the correct answer, not an
                    // error: the caller asked for an audit, not for us to keep one.
                    ReportId = result.Retention.ReportRetained ? result.Report.Id.ToString() : null,
                    ReportRetained = result.Retention.ReportRetained,
                    BundlePurged = result.Retention.BundlePurged,
                    Framing = result.Report.Framing,
                    Summary = result.Report.Summary,
                    Outcome = result.Audit.Outcome.ToString(),
                    Rounds = result.Audit.Rounds,
                    Citations = result.Report.Citations.Count,
                },
                result.Retention.ReportRetained
                    ? "audit complete; report retained"
                    : "audit complete; report not retained (the submitter did not opt in)",
                HttpStatusCode.OK);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Audit stage failed for scan job {ScanJobId}", job.Id);
            await RecordFailureAsync(job, ex);

            return await Response.FailureAsync(
                $"audit stage failed: {ex.Message}", HttpStatusCode.InternalServerError);
        }
    }

    /// <summary>Mirrors the graph stage: record the reason without letting a second failure escape.</summary>
    private async Task RecordFailureAsync(ScanJob job, Exception failure)
    {
        try
        {
            unitOfWork.DiscardChanges();
            await AdvanceStageAsync(job, job.Stage, failure.Message);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Could not record the audit-stage failure on scan job {ScanJobId}", job.Id);
        }
    }

    private async Task AdvanceStageAsync(ScanJob job, ScanStage stage, string? failure)
    {
        var tracked = await unitOfWork.Repository<ScanJob>()
            .GetTableAsTracked()
            .FirstOrDefaultAsync(j => j.Id == job.Id);

        if (tracked is null) return;

        tracked.Stage = stage;
        tracked.FailureReason = failure;

        if (failure is null && stage == ScanStage.Report)
        {
            tracked.Status = ScanStatus.Completed;
            tracked.CompletedAt = DateTime.UtcNow;
        }

        await unitOfWork.CompleteAsync();
    }
}

/// <summary>What the audit stage produced, in the read API's wire style.</summary>
public sealed record RunAuditStageResponse
{
    [JsonPropertyName("scan_job_id")] public required string ScanJobId { get; init; }

    /// <summary>Null when the report was not retained — there is no id to fetch.</summary>
    [JsonPropertyName("report_id")] public string? ReportId { get; init; }

    [JsonPropertyName("report_retained")] public required bool ReportRetained { get; init; }
    [JsonPropertyName("bundle_purged")] public required bool BundlePurged { get; init; }
    [JsonPropertyName("framing")] public required string Framing { get; init; }
    [JsonPropertyName("summary")] public required string Summary { get; init; }
    [JsonPropertyName("outcome")] public required string Outcome { get; init; }
    [JsonPropertyName("rounds")] public required int Rounds { get; init; }
    [JsonPropertyName("citations")] public required int Citations { get; init; }
}

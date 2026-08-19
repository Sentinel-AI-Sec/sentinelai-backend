using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Queries.GetById;

public sealed record ScanJobResponse
{
    public required string ScanJobId { get; init; }
    public required ScanStatus Status { get; init; }
    public required ScanStage Stage { get; init; }
    public required string CorpusVersion { get; init; }

    /// <summary>
    /// The audit this scan produced, once it has one — <c>null</c> until the audit stage
    /// completes, and null afterwards for a scan that did not ask to keep its report.
    /// </summary>
    /// <remarks>
    /// Surfaced here because there is no other way to reach it. <c>GET /v1/reports/{id}</c>
    /// takes a report id, and the only response that ever carried one was
    /// <c>POST /v1/scans/{id}/audit</c> — which nothing calls now that SEC-46's worker drives
    /// the pipeline. A worker-driven scan therefore produced a report no caller could find:
    /// the Action could not put it in its PR comment and the dashboard could not link to it.
    /// The join already exists (<c>GetForTenantAsync</c> includes the report), so this only
    /// stops throwing the answer away.
    /// </remarks>
    public string? ReportId { get; init; }
    public required bool BundlePurged { get; init; }
    public string? FailureReason { get; init; }
    public required DateTime StartedAt { get; init; }
    public DateTime? CompletedAt { get; init; }

    public static ScanJobResponse From(ScanJob job) => new()
    {
        ScanJobId = job.Id.ToString(),
        Status = job.Status,
        Stage = job.Stage,
        CorpusVersion = job.CorpusVersion,
        ReportId = job.Report?.Id.ToString(),
        BundlePurged = job.BundlePurged,
        FailureReason = job.FailureReason,
        StartedAt = job.StartedAt,
        CompletedAt = job.CompletedAt,
    };
}

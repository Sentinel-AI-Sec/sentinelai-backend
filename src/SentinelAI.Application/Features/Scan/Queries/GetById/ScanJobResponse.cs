using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Queries.GetById;

public sealed record ScanJobResponse
{
    public required string ScanJobId { get; init; }
    public required ScanStatus Status { get; init; }
    public required ScanStage Stage { get; init; }
    public required string CorpusVersion { get; init; }
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
        BundlePurged = job.BundlePurged,
        FailureReason = job.FailureReason,
        StartedAt = job.StartedAt,
        CompletedAt = job.CompletedAt,
    };
}

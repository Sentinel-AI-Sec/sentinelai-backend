namespace SentinelAI.Application.Features.Scan.Orchestration;

/// <summary>
/// What one automated run of Pipeline B did (SEC-46).
/// </summary>
/// <remarks>
/// Returned rather than thrown, because the worker's correct response to a failed scan is the
/// same as to a successful one — log it and go back for the next job. An exception escaping the
/// runner would make "this scan failed" and "the worker is broken" the same event at the call
/// site, and only one of those should stop anything.
/// </remarks>
public sealed record ScanRunOutcome
{
    public required Guid ScanJobId { get; init; }

    /// <summary>False when a stage threw. The job row has been marked failed either way.</summary>
    public required bool Succeeded { get; init; }

    /// <summary>Which block threw. Null on success.</summary>
    public ScanPipelineStage? FailedStage { get; init; }

    /// <summary>The exception's message, as written to <c>ScanJob.FailureReason</c>. Null on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary>How many findings the normalize stage produced. Zero on an early failure.</summary>
    public int Findings { get; init; }

    /// <summary>How many candidate chains the graph stage found. Zero is a legitimate result.</summary>
    public int CandidateChains { get; init; }

    public static ScanRunOutcome Success(Guid scanJobId, int findings, int chains) => new()
    {
        ScanJobId = scanJobId,
        Succeeded = true,
        Findings = findings,
        CandidateChains = chains,
    };

    public static ScanRunOutcome Failure(
        Guid scanJobId, ScanPipelineStage stage, string reason, int findings = 0, int chains = 0) => new()
    {
        ScanJobId = scanJobId,
        Succeeded = false,
        FailedStage = stage,
        FailureReason = reason,
        Findings = findings,
        CandidateChains = chains,
    };
}

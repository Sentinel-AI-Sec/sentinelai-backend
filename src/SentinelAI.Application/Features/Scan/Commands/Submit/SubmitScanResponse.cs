using SentinelAI.Domain.Enums;

namespace SentinelAI.Application.Features.Scan.Commands.Submit;

public sealed record SubmitScanResponse
{
    public required string ScanJobId { get; init; }
    public required ScanStatus Status { get; init; }
    public required string CorpusVersion { get; init; }
    public required string PollUrl { get; init; }
    public required string BundleSha256 { get; init; }
    public required DateTime CreatedAt { get; init; }
}

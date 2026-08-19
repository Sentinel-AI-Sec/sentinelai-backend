using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// Retention without a database, for the tests whose subject is a different stage.
/// </summary>
/// <remarks>
/// It records what it was asked to do rather than doing nothing silently: a no-op double would
/// let the pipeline quietly stop calling retention and every one of those tests would still
/// pass. <c>ScanRetentionTests</c> and <c>AccountDeletionTests</c> exercise the real policy
/// against a real provider.
/// </remarks>
internal sealed class FakeScanRetentionPolicy(bool retainReport = false) : IScanRetentionPolicy
{
    /// <summary>Every job retention was applied to, in order.</summary>
    public List<Guid> AppliedTo { get; } = [];

    public Task<RetentionOutcome> ApplyAfterAuditAsync(
        Guid tenantId, Guid scanJobId, Report report, CancellationToken ct = default)
    {
        AppliedTo.Add(scanJobId);
        report.Retained = retainReport;

        return Task.FromResult(new RetentionOutcome(BundlePurged: true, ReportRetained: retainReport));
    }
}

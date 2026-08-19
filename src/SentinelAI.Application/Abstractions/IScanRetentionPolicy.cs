using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Abstractions;

/// <summary>What retention actually did to one finished scan.</summary>
/// <param name="BundlePurged">
/// The received bundle was deleted from storage (or was already gone — the call is idempotent).
/// </param>
/// <param name="ReportRetained">
/// The report was kept because the submitter opted in. False means it was produced, returned to
/// the caller, and never written down.
/// </param>
public sealed record RetentionOutcome(bool BundlePurged, bool ReportRetained);

/// <summary>
/// Applies the data-retention promise once an audit finishes (SEC-35).
/// </summary>
/// <remarks>
/// <para>
/// Two rules, and both default to <em>not keeping</em> things:
/// </para>
/// <list type="number">
///   <item>The received bundle is deleted. It was needed to produce findings; once the audit
///   exists it is customer material we have no further use for.</item>
///   <item>The report is stored only if the submitter asked for it via
///   <c>metadata.retain_report</c>. Silence means delete.</item>
/// </list>
/// <para>
/// This is an interface rather than a concrete call inside the pipeline because retention is a
/// policy, and a policy that cannot be substituted cannot be tested at the boundary that
/// matters — "did the bundle actually leave the disk" is a different question from "did the
/// pipeline ask for it to".
/// </para>
/// </remarks>
public interface IScanRetentionPolicy
{
    /// <summary>
    /// Purges the bundle and decides the report's fate. Safe to call more than once for the
    /// same job.
    /// </summary>
    /// <param name="report">
    /// The freshly built report. Its <see cref="Report.Retained"/> flag is set here — the
    /// builder cannot know the answer, because the opt-in lives on the scan job.
    /// </param>
    Task<RetentionOutcome> ApplyAfterAuditAsync(
        Guid tenantId, Guid scanJobId, Report report, CancellationToken ct = default);
}

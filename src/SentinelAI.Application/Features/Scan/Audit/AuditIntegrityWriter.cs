using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Audit;

/// <summary>
/// Records what could be checked about one scan's own reasoning.
/// </summary>
/// <remarks>
/// <para>
/// Called at the end of the audit stage, after the chain outcome has been written, because the
/// chain counts are part of what it records. It is bookkeeping around the stages rather than a
/// stage itself, which is why it lives beside the runner's other bookkeeping.
/// </para>
/// <para>
/// <b>It never throws into the pipeline.</b> A failed self-check must not fail a scan that
/// succeeded: the customer's audit is real work and this row is an observation about it. The
/// failure is logged at Error, where it will be noticed, and the scan completes — the same
/// defensive shape <c>RecordFailureAsync</c> has for the same reason.
/// </para>
/// </remarks>
public sealed class AuditIntegrityWriter(IUnitOfWork unitOfWork, ILogger<AuditIntegrityWriter> logger)
{
    /// <summary>
    /// Bumped when what these checks measure changes.
    /// </summary>
    /// <remarks>
    /// Not a schema version. It answers "are these two rows comparable?", which is the first
    /// question anyone asks of a trend, and the one a timestamp cannot answer.
    /// </remarks>
    public const int Version = 1;

    public async Task WriteAsync(
        Guid tenantId,
        Guid scanJobId,
        DraftAudit audit,
        RetrievalEvaluation? evaluation,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(audit);

        try
        {
            var chains = await unitOfWork.Repository<Chain>()
                .GetTableAsNotTracked()
                .Where(c => c.ScanJobId == scanJobId)
                .Select(c => c.Status)
                .ToListAsync(ct);

            var row = new ScanAuditIntegrity
            {
                Id = Guid.CreateVersion7(),
                TenantId = tenantId,
                ScanJobId = scanJobId,

                Adjudicated = audit.Adjudicated,
                Outcome = audit.Outcome.ToString(),
                Rounds = audit.Rounds,
                VerdictReadable = audit.VerdictReadable,
                TerminatedByTurnCap = audit.TerminatedByTurnCap,
                WeakestJoin = audit.WeakestJoin.ToString(),

                EdgeIntegrityWarnings = audit.EdgeIntegrityWarnings.Count,
                EdgeIntegrityDetail = Join(audit.EdgeIntegrityWarnings),
                AbandonedReasoningWarnings = audit.AbandonedReasoningWarnings.Count,
                AbandonedReasoningDetail = Join(audit.AbandonedReasoningWarnings),

                RetrievalFindings = evaluation?.Findings ?? 0,
                RetrievalGrounded = evaluation?.Grounded ?? 0,
                // 100 when nothing needed grounding, matching RetrievalEvaluation's own reading of
                // the empty case: no findings is full coverage of no findings, not a total miss.
                CoveragePercent = evaluation?.CoveragePercent ?? 100,
                ModesThatDidNotFire = evaluation is null
                    ? string.Empty
                    : string.Join(",", evaluation.ModesThatDidNotFire),

                CandidateChains = chains.Count,
                ChainsAdjudicated = chains.Count(s => s != ChainStatus.Candidate),

                CorpusVersion = audit.CorpusVersion ?? string.Empty,
                HarnessVersion = Version,
                CreatedAt = DateTime.UtcNow,
            };

            await unitOfWork.Repository<ScanAuditIntegrity>().AddAsync(row);
            await unitOfWork.CompleteAsync();

            // Logged at Warning when the graph contradicted something an agent asserted in the
            // chain it reported. That is the one number here that should ever interrupt somebody.
            if (row.EdgeIntegrityWarnings > 0)
            {
                logger.LogWarning(
                    "Scan {ScanJobId}: {Count} asserted hop(s) in the reported chain are not "
                    + "supported by the graph. The chain was capped accordingly.",
                    scanJobId, row.EdgeIntegrityWarnings);
            }

            logger.LogInformation(
                "Audit integrity for scan {ScanJobId}: outcome {Outcome} in {Rounds} round(s), "
                + "{Grounded}/{Findings} grounded, {Adjudicated}/{Candidates} chain(s) adjudicated.",
                scanJobId, row.Outcome, row.Rounds, row.RetrievalGrounded, row.RetrievalFindings,
                row.ChainsAdjudicated, row.CandidateChains);
        }
        catch (Exception ex)
        {
            // Deliberately broad. Whatever went wrong here, the scan it describes already
            // succeeded, and losing the observation is strictly better than losing the audit.
            logger.LogError(ex,
                "Could not record audit integrity for scan {ScanJobId}. The scan itself is "
                + "unaffected.", scanJobId);
        }
    }

    /// <summary>
    /// Warnings as text, newline separated.
    /// </summary>
    /// <remarks>
    /// A column rather than a child table. They are read by a human looking at one scan, never
    /// queried across scans — the count is what gets aggregated — so a table would buy nothing and
    /// cost a join, a migration and a delete ordering.
    /// </remarks>
    private static string Join(IReadOnlyList<string> warnings) =>
        warnings.Count == 0 ? string.Empty : string.Join('\n', warnings);
}

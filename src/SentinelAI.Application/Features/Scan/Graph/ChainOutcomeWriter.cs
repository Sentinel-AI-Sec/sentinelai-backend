using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Graph;

/// <summary>
/// Promotes the audit stage's own record of what happened onto the graph stage's chain row, so
/// a reader of <c>GET /v1/scans/{id}/chains</c> sees more than "candidate" forever.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="CandidateChainWriter"/> leaves every <see cref="Chain"/> at
/// <see cref="ChainStatus.Candidate"/>, by its own comment: "Red fills the technique, Blue the
/// validation... none of which has run at this stage." This is that later stage — but only the
/// chain-level status, not the per-hop <see cref="ChainHop.TechniqueId"/> or
/// <see cref="ChainHop.BlueValidated"/>. Those live in Red and Blue's free-text turns, and
/// parsing debate prose into per-hop structured fields is exactly the "retrofit" SEC-28's own
/// acceptance criterion says to defer, not something to improvise here.
/// </para>
/// <para>
/// The debate reasons over one graph, not one identified <see cref="Chain"/> row — SEC-26's Red
/// asserts "the strongest chain," which is <c>ExploitChainTraverser</c>'s own
/// <c>Priority == 1</c> candidate by construction (its ranking is what Red reads top-down; see
/// <c>ExploitChainTraverser.Rank</c>). That is the row this outcome is written onto. A scan job
/// with no persisted chains — the walking skeleton, or a graph with no candidates — has nothing
/// to promote, and that is not an error.
/// </para>
/// </remarks>
public sealed class ChainOutcomeWriter(IUnitOfWork unitOfWork, ILogger<ChainOutcomeWriter> logger)
{
    public async Task ApplyAsync(Guid scanJobId, DraftAudit audit, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(audit);

        var chains = await unitOfWork.Repository<Chain>().GetWhereAsync(c => c.ScanJobId == scanJobId);
        var top = chains.OrderBy(c => c.Priority).FirstOrDefault();

        if (top is null) return;

        var status = StatusFor(audit.Outcome);
        top.Status = status;

        await unitOfWork.Repository<Chain>().UpdateAsync(top);
        await unitOfWork.CompleteAsync();

        logger.LogInformation(
            "Chain {ChainId} for scan job {ScanJobId} promoted to {Status} on debate outcome {Outcome}",
            top.Id, scanJobId, status, audit.Outcome);
    }

    /// <summary>
    /// A definite Blue verdict promotes or rejects the chain. Anything short of one — the
    /// turn-cap or an unparseable verdict — only reaches <see cref="ChainStatus.Asserted"/>:
    /// Red did run, but nothing confirmed or refuted what it asserted, and "unreadable" or
    /// "ran out of turns" is not evidence the chain is real or fake (AID-01 §3.3).
    /// </summary>
    private static ChainStatus StatusFor(DebateOutcome outcome) => outcome switch
    {
        DebateOutcome.Converged => ChainStatus.Validated,
        DebateOutcome.ChainBroken => ChainStatus.Rejected,
        DebateOutcome.TurnCapped => ChainStatus.Asserted,
        DebateOutcome.VerdictUnreadable => ChainStatus.Asserted,
        _ => ChainStatus.Asserted,
    };
}

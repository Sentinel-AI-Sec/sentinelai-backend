using Microsoft.Extensions.Logging;
using SentinelAI.Application.Debate;
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
/// validation... none of which has run at this stage." This is that later stage, and as of
/// audit 42-A it writes both halves: the chain-level status, <em>and</em> the per-hop
/// <see cref="ChainHop.BlueVerdict"/> and <see cref="ChainHop.TechniqueId"/> that
/// <see cref="HopVerdictReader"/> can recover from Red's and Blue's turns.
/// </para>
/// <para>
/// This used to say per-hop fields were deferred, and they were — for long enough that the
/// dashboard shipped "Blue validated 0 of N steps" and an empty ATT&amp;CK link on every chain
/// the system had ever produced, because an unwritten column reads exactly like a measured
/// zero. What changed is not confidence in parsing prose; it is that a hop the transcript does
/// not settle is now <em>representable</em>. <see cref="HopVerdict.Unattributed"/> says "Blue
/// was read and said nothing about this hop" and <see cref="HopVerdict.Unassessed"/> says "no
/// debate has looked at all" — so the writer never has to choose between inventing a verdict
/// and pretending it measured one.
/// </para>
/// <para>
/// The per-hop write needs the <see cref="ScanBrief"/> as well as the audit, for the same
/// reason <see cref="EdgeAssertionValidator"/> does: the <c>N&lt;n&gt;</c> labels the agents
/// write mean nothing except against the brief that defined them. A null brief — a caller that
/// has an audit but not the text behind it — writes the chain status only, which is precisely
/// this class's behaviour before 42-A.
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
    /// <param name="brief">
    /// The brief the debate actually read, or null when the caller does not have it. It is the
    /// only thing that can turn the <c>N&lt;n&gt;</c> labels in the transcript back into node
    /// keys, so without it the per-hop pass is skipped entirely and the hops keep whatever
    /// verdict they already had — never a fresh <c>false</c> standing in for "we could not
    /// look".
    /// </param>
    public async Task ApplyAsync(Guid scanJobId, DraftAudit audit, ScanBrief? brief, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(audit);

        var chains = await unitOfWork.Repository<Chain>().GetWhereAsync(c => c.ScanJobId == scanJobId);
        var top = chains.OrderBy(c => c.Priority).FirstOrDefault();

        if (top is null) return;

        var status = StatusFor(audit);
        top.Status = status;

        await unitOfWork.Repository<Chain>().UpdateAsync(top);

        var hops = await ApplyHopOutcomesAsync(scanJobId, top, audit, brief);

        await unitOfWork.CompleteAsync();

        logger.LogInformation(
            "Chain {ChainId} for scan job {ScanJobId} promoted to {Status} on debate outcome "
            + "{Outcome}; {Confirmed} hop(s) confirmed, {Unresolved} unresolved, {Refuted} refuted, "
            + "{Unattributed} not attributable to anything Blue said, {Techniques} with a grounded "
            + "ATT&CK technique",
            top.Id, scanJobId, status, audit.Outcome,
            hops.Confirmed, hops.Unresolved, hops.Refuted, hops.Unattributed, hops.Techniques);
    }

    /// <summary>How the per-hop pass went, for one honest log line.</summary>
    private readonly record struct HopTally(
        int Confirmed, int Unresolved, int Refuted, int Unattributed, int Techniques)
    {
        /// <summary>No pass ran — not "a pass that found nothing".</summary>
        public static HopTally NotRun => new(0, 0, 0, 0, 0);
    }

    /// <summary>
    /// Writes what the transcript says about each hop of the chain being promoted (audit 42-A).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The last Red and Blue turns, not every turn.</b> Same choice, for the same reason, as
    /// <see cref="EdgeIntegrityDebateEngine"/>: earlier rounds may have asserted a chain that was
    /// then broken and abandoned, and a verdict on a hop of a discarded chain is not a verdict on
    /// this one. A live run had Red pivot between rounds after Blue killed its first path.
    /// </para>
    /// <para>
    /// <b>The top chain only.</b> Red is asked for "the strongest chain", which is the
    /// <c>Priority == 1</c> candidate by construction, and that is the row whose status is being
    /// promoted here. An edge Blue confirmed may well appear in some other candidate too, but
    /// Blue judged it as a link in the chain it was shown; copying the verdict sideways would be
    /// this class asserting something Blue did not.
    /// </para>
    /// <para>
    /// <b>The seed hop can never be attributed.</b> Its <c>EdgeId</c> is null — it arrived from
    /// nowhere — and every anchor in the transcript is a node <em>pair</em>. It stays
    /// <see cref="HopVerdict.Unattributed"/>, which is true: Blue validates joins, and the seed
    /// is not one.
    /// </para>
    /// <para>
    /// <b>An existing technique id is never cleared.</b> Absence of an id in this transcript is
    /// not evidence against one already recorded; a verdict, by contrast, is rewritten every time
    /// a debate is run over the chain, because it is that debate's answer.
    /// </para>
    /// </remarks>
    private async Task<HopTally> ApplyHopOutcomesAsync(
        Guid scanJobId, Chain top, DraftAudit audit, ScanBrief? brief)
    {
        if (brief is null || string.IsNullOrWhiteSpace(brief.Context)) return HopTally.NotRun;

        var blue = audit.Transcript.LastOrDefault(t => t.Role == AgentRole.Blue);
        var red = audit.Transcript.LastOrDefault(t => t.Role == AgentRole.Red);

        if (blue is null && red is null) return HopTally.NotRun;

        var hops = (await unitOfWork.Repository<ChainHop>().GetWhereAsync(h => h.ChainId == top.Id))
            .OrderBy(h => h.HopOrder)
            .ToList();

        if (hops.Count == 0) return HopTally.NotRun;

        // The two lookups that turn a hop row back into the node pair the transcript names it by.
        var keyByNodeId = (await unitOfWork.Repository<GraphNode>().GetWhereAsync(n => n.ScanJobId == scanJobId))
            .ToDictionary(n => n.Id, n => n.NodeKey);

        var edgesById = (await unitOfWork.Repository<GraphEdge>().GetWhereAsync(e => e.ScanJobId == scanJobId))
            .ToDictionary(e => e.Id);

        var verdicts = blue is null
            ? new Dictionary<HopRef, HopVerdict>()
            : HopVerdictReader.ReadVerdicts(brief.Context, blue.Content);

        var techniques = red is null
            ? new Dictionary<HopRef, string>()
            : HopVerdictReader.ReadTechniques(brief.Context, red.Content);

        var tally = HopTally.NotRun;

        foreach (var hop in hops)
        {
            var reference = ReferenceFor(hop, edgesById, keyByNodeId);

            if (blue is not null)
            {
                hop.BlueVerdict = reference is { } r && verdicts.TryGetValue(r, out var verdict)
                    ? verdict
                    // Blue was read and this hop is not in what it said. That is a fact about the
                    // transcript, not a judgement about the hop — see HopVerdict.Unattributed.
                    : HopVerdict.Unattributed;
            }

            if (reference is { } t && techniques.TryGetValue(t, out var technique))
                hop.TechniqueId = technique;

            tally = tally with
            {
                Confirmed = tally.Confirmed + (hop.BlueVerdict == HopVerdict.Confirmed ? 1 : 0),
                Unresolved = tally.Unresolved + (hop.BlueVerdict == HopVerdict.Unresolved ? 1 : 0),
                Refuted = tally.Refuted + (hop.BlueVerdict == HopVerdict.Refuted ? 1 : 0),
                Unattributed = tally.Unattributed + (hop.BlueVerdict == HopVerdict.Unattributed ? 1 : 0),
                Techniques = tally.Techniques + (hop.TechniqueId.Length > 0 ? 1 : 0),
            };

            await unitOfWork.Repository<ChainHop>().UpdateAsync(hop);
        }

        return tally;
    }

    /// <summary>
    /// The node pair a hop row is named by in the transcript, or null when it has none.
    /// </summary>
    /// <remarks>
    /// Null for the seed hop, and for the shouldn't-happen cases — an edge id with no edge, an
    /// edge whose endpoints are not among this scan's nodes. Those are returned as "cannot be
    /// referenced" rather than thrown on: a broken lookup must cost the hop its verdict, not the
    /// whole audit its write-back.
    /// </remarks>
    private static HopRef? ReferenceFor(
        ChainHop hop,
        IReadOnlyDictionary<Guid, GraphEdge> edgesById,
        IReadOnlyDictionary<Guid, string> keyByNodeId)
    {
        if (hop.EdgeId is not { } edgeId || !edgesById.TryGetValue(edgeId, out var edge))
            return null;

        return keyByNodeId.TryGetValue(edge.FromNodeId, out var from)
            && keyByNodeId.TryGetValue(edge.ToNodeId, out var to)
                ? new HopRef(from, to)
                : null;
    }

    /// <summary>
    /// A definite Blue verdict promotes or rejects the chain. Anything short of one — the
    /// turn-cap or an unparseable verdict — only reaches <see cref="ChainStatus.Asserted"/>:
    /// Red did run, but nothing confirmed or refuted what it asserted, and "unreadable" or
    /// "ran out of turns" is not evidence the chain is real or fake (AID-01 §3.3).
    /// </summary>
    /// <remarks>
    /// SEC-50: a <see cref="DebateOutcome.Converged"/> result never reaches
    /// <see cref="ChainStatus.Validated"/> when <see cref="DraftAudit.EdgeIntegrityWarnings"/> is
    /// non-empty — a hop in the chain the Reporter actually reported that does not match the
    /// graph. Blue's own verdict said the chain holds; the mechanical check is what caught the
    /// live case where Blue was wrong to say so — a reversed-direction edge it read as confirmed.
    /// The chain still gets asserted, not rejected: a mismatched node pair is evidence the check
    /// should not be trusted blindly, not proof the chain is fake either.
    /// <para>
    /// Deliberately not <see cref="DraftAudit.AbandonedReasoningWarnings"/> — a hop Red or Blue
    /// considered and the Reporter itself dropped from the final chain is not evidence against
    /// the chain that was actually reported. A live run had Red assert a fabricated path
    /// alongside a genuinely valid one in the same turn; the Reporter reported only the valid
    /// one, and that chain does not deserve to be capped for reasoning nobody acted on.
    /// </para>
    /// </remarks>
    private static ChainStatus StatusFor(DraftAudit audit)
    {
        var outcome = audit.Outcome switch
        {
            DebateOutcome.Converged => ChainStatus.Validated,
            DebateOutcome.ChainBroken => ChainStatus.Rejected,
            DebateOutcome.TurnCapped => ChainStatus.Asserted,
            DebateOutcome.VerdictUnreadable => ChainStatus.Asserted,
            _ => ChainStatus.Asserted,
        };

        return outcome == ChainStatus.Validated && audit.EdgeIntegrityWarnings.Count > 0
            ? ChainStatus.Asserted
            : outcome;
    }
}

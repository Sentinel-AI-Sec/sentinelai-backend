using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Tests;

/// <summary>
/// Pure contract rules — no workflow, no model, no I/O. These encode invariants from
/// AID-01 that the rest of the system is entitled to rely on.
/// </summary>
public class DebateContractTests
{
    // AID-01 3.3: a chain inherits its weakest edge's confidence. Confidence is shared with
    // the graph (GraphEdge.Confidence), so this pins the ordering against a well-meaning
    // reorder in someone else's PR — reordering compiles fine and inverts the rule silently.
    [Fact]
    public void Confidence_orders_weakest_first()
    {
        Assert.True(Confidence.Unresolved < Confidence.Inferred);
        Assert.True(Confidence.Inferred < Confidence.Certain);
    }

    [Fact]
    public void Chain_inherits_its_weakest_join()
    {
        Confidence[] chain = [Confidence.Certain, Confidence.Unresolved, Confidence.Certain];
        Assert.Equal(Confidence.Unresolved, chain.Weakest());

        Confidence[] inferredChain = [Confidence.Certain, Confidence.Inferred];
        Assert.Equal(Confidence.Inferred, inferredChain.Weakest());
    }

    // Nothing asserted means nothing to doubt. Guards the empty-transcript path the Reporter
    // hits when the debate produced no turns.
    [Fact]
    public void Weakest_of_nothing_is_certain()
    {
        Assert.Equal(Confidence.Certain, Array.Empty<Confidence>().Weakest());
        Assert.Equal(Confidence.Certain, Array.Empty<DebateTurn>().Weakest(t => t.Confidence));
    }

    // The debate's verdict has to be writable onto a graph edge without a translation table.
    [Fact]
    public void Debate_and_graph_speak_the_same_confidence_type()
    {
        var turn = Turn(AgentRole.Blue) with { Confidence = Confidence.Inferred };
        var edge = new GraphEdge { Confidence = turn.Confidence };

        Assert.Equal(turn.Confidence, edge.Confidence);
    }

    [Fact]
    public void Appending_a_turn_does_not_mutate_the_original_state()
    {
        var original = new DebateState();
        var appended = original.Append(Turn(AgentRole.Red));

        Assert.Empty(original.Transcript);
        Assert.Single(appended.Transcript);
        Assert.Equal(1, appended.TurnCount);
    }

    // Round is serialized into every checkpoint. It was documented as "incremented by Red"
    // and incremented by nothing, so a resumed run read round 0 however far the debate got.
    [Fact]
    public void State_tracks_the_highest_round_reached()
    {
        var state = new DebateState()
            .Append(Turn(AgentRole.Red, round: 1))
            .Append(Turn(AgentRole.Blue, round: 1))
            .Append(Turn(AgentRole.Red, round: 2));

        Assert.Equal(2, state.Round);

        // The Reporter closes the round it was handed; that must not walk the count back.
        Assert.Equal(2, state.Append(Turn(AgentRole.Reporter, round: 2)).Round);
    }

    // An unparseable verdict must never be reported as a convergence. Ordered
    // most-doubtful-first, so this is the precedence that protects that.
    [Fact]
    public void Unreadable_verdict_outranks_every_other_outcome()
    {
        var audit = Audit(converged: true, cappedOut: true, verdictReadable: false);
        Assert.Equal(DebateOutcome.VerdictUnreadable, audit.Outcome);
    }

    [Theory]
    [InlineData(true, true, DebateOutcome.TurnCapped)]
    [InlineData(true, false, DebateOutcome.Converged)]
    [InlineData(false, true, DebateOutcome.TurnCapped)]
    [InlineData(false, false, DebateOutcome.ChainBroken)]
    public void Outcome_reports_how_the_debate_actually_ended(
        bool converged, bool cappedOut, DebateOutcome expected)
    {
        Assert.Equal(expected, Audit(converged, cappedOut, verdictReadable: true).Outcome);
    }

    // AID-01 7: the output is a draft for human review, never a verified verdict. The
    // framing is a computed property so a caller cannot omit it.
    [Fact]
    public void Every_audit_carries_the_draft_framing()
    {
        var audit = Audit(converged: true, cappedOut: false, verdictReadable: true);

        Assert.Contains("draft audit", audit.Disclaimer, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not a verified verdict", audit.Disclaimer, StringComparison.OrdinalIgnoreCase);
    }

    private static DebateTurn Turn(AgentRole role, int round = 1) =>
        new() { Role = role, Round = round, Content = "turn" };

    private static DraftAudit Audit(bool converged, bool cappedOut, bool verdictReadable) => new()
    {
        Summary = "summary",
        Transcript = [Turn(AgentRole.Reporter)],
        Rounds = 1,
        TerminatedByTurnCap = cappedOut,
        Converged = converged,
        VerdictReadable = verdictReadable
    };
}

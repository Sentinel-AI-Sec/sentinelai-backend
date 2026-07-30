using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Tests;

/// <summary>
/// Pure contract rules — no workflow, no model, no I/O. These encode invariants from
/// AID-01 that the rest of the system is entitled to rely on.
/// </summary>
public class DebateContractTests
{
    // AID-01 3.3: a chain inherits its weakest edge's confidence. The enum is ordered
    // weakest-first precisely so Min() *is* that rule.
    [Fact]
    public void Join_confidence_orders_weakest_first()
    {
        Assert.True(JoinConfidence.Unresolved < JoinConfidence.Inferred);
        Assert.True(JoinConfidence.Inferred < JoinConfidence.Certain);

        JoinConfidence[] chain = [JoinConfidence.Certain, JoinConfidence.Unresolved, JoinConfidence.Certain];
        Assert.Equal(JoinConfidence.Unresolved, chain.Min());
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

    private static DebateTurn Turn(AgentRole role) =>
        new() { Role = role, Round = 1, Content = "turn" };

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

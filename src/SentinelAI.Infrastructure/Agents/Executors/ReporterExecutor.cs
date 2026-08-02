using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Agents.Executors;

/// <summary>
/// Adjudicates the debate transcript into a prioritized, cited draft audit (AID-01 3.1).
/// </summary>
/// <remarks>
/// The Reporter is reached on BOTH exit paths — convergence and turn-cap — which is what
/// guarantees SEC-02's "turn-cap exceeded → orchestrator terminates cleanly; Reporter
/// still outputs". It is the only executor that yields workflow output and halts the run.
/// </remarks>
public sealed class ReporterExecutor(AIAgent agent, int maxRounds)
    : DebateExecutor<DraftAudit>(ExecutorId, agent, AgentRole.Reporter)
{
    /// <summary>Node id in the workflow graph. Named to avoid shadowing <c>Executor.Id</c>.</summary>
    public const string ExecutorId = "reporter";

    public const string Instructions =
        """
        You are the Reporter agent. Read the debate transcript and assemble the surviving,
        validated chains into a prioritized draft audit ranked by severity and exploitability.
        Every assertion must carry its citation. A chain resting on an unresolved join is
        reported as "potential chain, unverified join" — never as a confirmed verdict.

        Answer directly. No preamble, no restating the transcript, no thinking aloud.
        At most six short lines.
        """;

    protected override string BuildPrompt(DebateTurn incoming, DebateState state) =>
        $"""
        {state.ResourceGraph}

        Adjudicate. {state.TurnCount} turns across {incoming.Round} round(s).
        {Quote(incoming.Role, incoming.Content)}
        """;

    protected override DebateTurn Interpret(string content, DebateTurn incoming, DebateState state) =>
        new()
        {
            Role = AgentRole.Reporter,
            Round = incoming.Round,
            Content = content,
            // The report can be no more certain than the weakest link it rests on.
            Confidence = incoming.Confidence,
            Converged = incoming.Converged,
            VerdictReadable = incoming.VerdictReadable
        };

    public override async ValueTask<DraftAudit> HandleAsync(
        DebateTurn message,
        IWorkflowContext context,
        CancellationToken cancellationToken = default)
    {
        var turn = await RunTurnAsync(message, context, cancellationToken).ConfigureAwait(false);

        // Re-read so the audit includes the Reporter's own turn.
        var state = await ReadStateAsync(context, cancellationToken).ConfigureAwait(false);
        var cappedOut = !message.Converged && message.Round >= maxRounds;

        await context
            .QueueStateUpdateAsync(
                DebateStateKeys.State,
                state with { Converged = message.Converged, TurnCapReached = cappedOut },
                DebateStateKeys.SharedScope,
                cancellationToken)
            .ConfigureAwait(false);

        var audit = BuildAudit(state, turn, cappedOut);
        await context.YieldOutputAsync(audit, cancellationToken).ConfigureAwait(false);

        // Clean termination — the orchestrator's job per AID-01 3.1.
        await context.RequestHaltAsync().ConfigureAwait(false);
        return audit;
    }

    private static DraftAudit BuildAudit(DebateState state, DebateTurn closing, bool cappedOut) => new()
    {
        Summary = closing.Content,
        Transcript = state.Transcript,
        Rounds = closing.Round,
        TerminatedByTurnCap = cappedOut,
        Converged = closing.Converged,
        VerdictReadable = closing.VerdictReadable,
        // The named rule, not Min(), so the enum's declaration order stops being load-bearing
        // for anyone reading this — the shared enum now has a second owner (the graph).
        WeakestJoin = state.Transcript.Weakest(t => t.Confidence)
    };
}

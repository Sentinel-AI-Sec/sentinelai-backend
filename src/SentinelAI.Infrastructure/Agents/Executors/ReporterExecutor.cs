using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Observability;

namespace SentinelAI.Infrastructure.Agents.Executors;

/// <summary>
/// Adjudicates the debate transcript into a prioritized, cited draft audit (AID-01 3.1).
/// </summary>
/// <remarks>
/// The Reporter is reached on BOTH exit paths — convergence and turn-cap — which is what
/// guarantees SEC-02's "turn-cap exceeded → orchestrator terminates cleanly; Reporter
/// still outputs". It is the only executor that yields workflow output and halts the run.
/// </remarks>
/// <param name="pricing">
/// Token rates used to turn the debate's measured usage into the cost figure SEC-31 puts on
/// the audit. Null records tokens without money, which is what an unpriced provider deserves.
/// </param>
public sealed class ReporterExecutor(
    AIAgent agent,
    int maxRounds,
    ModelTier tier = ModelTier.High,
    ModelPricing? pricing = null,
    TurnTracing? tracing = null)
    : DebateExecutor<DraftAudit>(ExecutorId, agent, AgentRole.Reporter, tier, tracing)
{
    /// <summary>Node id in the workflow graph. Named to avoid shadowing <c>Executor.Id</c>.</summary>
    public const string ExecutorId = "reporter";

    /// <summary>Instructions the backing <c>ChatClientAgent</c> is created with.</summary>
    /// <remarks>
    /// The labelled lines are what make this turn readable as a result rather than as the end of
    /// a conversation. "At most six short lines" produced six lines of prose that restated the
    /// chain and left the reader to work out how bad it was, what was still unproven, and what
    /// to do next — the three things a draft audit is for. Fixing the labels also gives the
    /// transcript panel something to render as fields, and gives <c>ChainOutcomeWriter</c> a
    /// CHAIN line to check rather than a sentence that may or may not contain one.
    /// </remarks>
    public const string Instructions =
        """
        You are the Reporter agent. Read the debate transcript and assemble the surviving,
        validated chains into a prioritized draft audit ranked by severity and exploitability.
        Every assertion must carry its citation. A chain resting on an unresolved join is
        reported as "potential chain, unverified join" — never as a confirmed verdict.

        Write exactly these lines, in this order, one line each and nothing else:
          CHAIN: <the surviving path as N? -> N? -> N?>
          SEVERITY: <critical|high|medium|low> — <one clause on why>
          CONFIDENCE: <certain|inferred|unresolved> — <the weakest join, as N? -> N?>
          IMPACT: <what an attacker reaches at the end of the chain>
          EVIDENCE: <the finding ids and config details the chain rests on>
          NEXT: <the one check that would settle the weakest join>

        If no chain survived, write CHAIN: none and say in SEVERITY why it did not.

        Answer directly. No preamble, no restating the transcript, no thinking aloud,
        no markdown.
        """;

    protected override string BuildPrompt(DebateTurn incoming, DebateState state) =>
        $"""
        {state.ResourceGraph}

        Adjudicate. {state.TurnCount} turns across {incoming.Round} round(s).
        {Quote(incoming.Role, incoming.Content)}

        Answer as the six labelled lines: CHAIN, SEVERITY, CONFIDENCE, IMPACT, EVIDENCE, NEXT.
        """;

    protected override DebateTurn Interpret(string content, DebateTurn incoming, DebateState state) =>
        new()
        {
            Role = AgentRole.Reporter,
            Round = incoming.Round,
            // This turn becomes DraftAudit.Summary, which is what the report screen shows and
            // what the audit is stored as — the one turn where leftover markdown or a <think>
            // block is not merely ugly in a transcript but is the published result.
            Content = TranscriptText.Clean(content),
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

        var audit = BuildAudit(state, turn, cappedOut, pricing);
        await context.YieldOutputAsync(audit, cancellationToken).ConfigureAwait(false);

        // Clean termination — the orchestrator's job per AID-01 3.1.
        await context.RequestHaltAsync().ConfigureAwait(false);
        return audit;
    }

    private static DraftAudit BuildAudit(
        DebateState state, DebateTurn closing, bool cappedOut, ModelPricing? pricing) => new()
    {
        Summary = closing.Content,
        Transcript = state.Transcript,
        Rounds = closing.Round,
        TerminatedByTurnCap = cappedOut,
        Converged = closing.Converged,
        VerdictReadable = closing.VerdictReadable,
        // The named rule, not Min(), so the enum's declaration order stops being load-bearing
        // for anyone reading this — the shared enum now has a second owner (the graph).
        WeakestJoin = state.Transcript.Weakest(t => t.Confidence),
        // AllTurns, not Transcript: the Orchestrator's briefing is a billed model call that
        // deliberately does not count as a debate turn, and leaving it out would under-report
        // every scan by one call.
        Cost = CostAccounting.Measure(state.AllTurns, pricing)
    };
}

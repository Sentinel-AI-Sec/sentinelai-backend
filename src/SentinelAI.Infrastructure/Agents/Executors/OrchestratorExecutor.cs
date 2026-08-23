using System.Diagnostics;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Observability;

namespace SentinelAI.Infrastructure.Agents.Executors;

/// <summary>
/// Entry point of the debate graph. Seeds shared session state and emits the opening
/// turn. When backed by a model it analyses the resource graph and produces a strategic
/// briefing for Red; without a model it passes the raw context through unchanged.
/// </summary>
public sealed class OrchestratorExecutor : Executor<ScanBrief, DebateTurn>
{
    /// <summary>Node id in the workflow graph. Named to avoid shadowing <c>Executor.Id</c>.</summary>
    public const string ExecutorId = "orchestrator";

    /// <summary>Instructions the backing <c>ChatClientAgent</c> is created with.</summary>
    /// <remarks>
    /// The labelled lines match the shape Red, Blue and the Reporter now answer in, so the four
    /// turns read as one document rather than as four house styles. Round 0's briefing is also
    /// the first thing a reader sees in the transcript, and "at most four short lines" of
    /// unlabelled prose gave them no way to tell the target from the aside.
    /// </remarks>
    public const string Instructions =
        """
        You are the Orchestrator agent in a security audit debate.
        Analyse the supplied resource graph and brief the Red Team agent on where to attack.
        Do NOT assert a chain yourself — that is Red's job.

        Write exactly these lines, in this order, one line each and nothing else:
          TARGET: <the crown-jewel node, as N? , and what it holds>
          LEAD: <the highest-severity finding, by its id, and why it is the way in>
          ROUTE: <the most promising layers to cross, named — not a hop-by-hop chain>
          WEAK JOIN: <the join Blue should scrutinise, as N? -> N?, and what would settle it>

        Answer directly. No preamble, no thinking aloud, no markdown.
        """;

    private readonly AIAgent? _agent;
    private readonly ModelTier _tier;
    private readonly TurnTracing? _tracing;

    /// <summary>Creates a model-backed orchestrator that analyses the brief via NIM.</summary>
    /// <param name="agent">The backing agent.</param>
    /// <param name="tier">
    /// The tier serving it — <see cref="ModelTier.Cheap"/> under the shipped policy, since
    /// briefing is the routine turn SEC-31 routes away from the reasoning model. Recorded on
    /// the seed turn so the audit's cost breakdown can charge it to the right tier.
    /// </param>
    /// <param name="tracing">
    /// Whether the seed turn's span may carry its prompt and answer (SEC-36). Null is metadata
    /// only.
    /// </param>
    public OrchestratorExecutor(AIAgent agent, ModelTier tier = ModelTier.Cheap, TurnTracing? tracing = null)
        : base(ExecutorId)
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));
        _tier = tier;
        _tracing = tracing;
    }

    /// <summary>
    /// Creates a pass-through orchestrator with no model call — the raw context is
    /// forwarded as the seed turn.
    /// </summary>
    /// <remarks>
    /// Tests only. Every provider, Scripted included, goes through
    /// <c>DebateWorkflow.CreateAgent</c> and gets the model-backed constructor above; the
    /// Scripted provider swaps the <c>IChatClient</c>, not the executor.
    /// </remarks>
    public OrchestratorExecutor() : base(ExecutorId) { }

    public override async ValueTask<DebateTurn> HandleAsync(
        ScanBrief message,
        IWorkflowContext context,
        CancellationToken cancellationToken = default)
    {
        // When a model is available, let it analyse the resource graph and produce a
        // strategic briefing. Otherwise pass the raw context through unchanged.
        var content = message.Context;
        var usage = TokenUsage.None;

        // SEC-36. Traced through the same helpers the other three agents use — this is the
        // second and last place a model call is made, and two call sites with two ways of
        // recording a turn is how the seed ends up missing from every trace.
        Activity? span = null;

        if (_agent is not null)
        {
            var prompt = $"Briefing for Red Team:\n{message.Context}";
            span = DebateTracing.StartTurn(AgentRole.Orchestrator, _tier, prompt, _tracing);

            try
            {
                var response = await _agent
                    .RunAsync(prompt, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);

                DebateTracing.RecordResponse(span, response, _tracing);

                // Cleaned like the other three turns. A briefing is quoted straight into Red's
                // first prompt, so a scratchpad left in it is not just noise on the screen —
                // it is another agent's thinking presented to Red as context.
                var briefing = TranscriptText.Clean(response.Text);
                if (briefing.Length > 0) content = briefing;
                usage = DebateExecutor<DebateTurn>.UsageOf(response);
            }
            catch (Exception ex)
            {
                DebateTracing.RecordFailure(span, ex);
                span?.Dispose();
                throw;
            }
        }

        var seed = new DebateTurn
        {
            Role = AgentRole.Orchestrator, // round 0 carries the brief, not an assertion
            Round = 0,
            Content = content,
            Tier = _tier,
            Usage = usage
        };

        // Closed here rather than in a `using` above, so the span covers the seed's construction
        // for the same reason the other three cover their interpretation — and so the round it
        // reports comes from the turn rather than from a literal repeated beside it.
        DebateTracing.RecordTurn(span, seed);
        span?.Dispose();

        // Round 0 seeds the state but is not itself a debate turn, so the transcript
        // starts empty and TurnCount counts only real agent turns. The seed is still kept
        // on the state — off to one side — because when the Orchestrator is model-backed it
        // is a billed call, and SEC-31's cost per audit is short by one without it.
        //
        // The pass-through orchestrator stores nothing: it made no model call, and a seed
        // recorded there would show up in the cost breakdown as a call that never happened.
        await context
            .QueueStateUpdateAsync(
                DebateStateKeys.State,
                new DebateState
                {
                    Round = 0,
                    ResourceGraph = message.Context,
                    Seed = _agent is null ? null : seed
                },
                DebateStateKeys.SharedScope,
                cancellationToken)
            .ConfigureAwait(false);

        return seed;
    }
}


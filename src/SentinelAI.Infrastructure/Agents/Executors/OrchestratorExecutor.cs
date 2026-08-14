using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using SentinelAI.Domain.Models;

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
    public const string Instructions =
        """
        You are the Orchestrator agent in a security audit debate.
        Analyse the supplied resource graph and produce a concise strategic briefing for the
        Red Team agent. Identify the highest-severity finding, the most promising cross-layer
        path through the graph, and any weak joins (e.g. image-name conventions) that Red
        should exploit or Blue should scrutinise. Do NOT assert a chain yourself — that is
        Red's job. Output only the briefing.

        Answer directly. No preamble, no thinking aloud. At most four short lines.
        """;

    private readonly AIAgent? _agent;
    private readonly ModelTier _tier;

    /// <summary>Creates a model-backed orchestrator that analyses the brief via NIM.</summary>
    /// <param name="agent">The backing agent.</param>
    /// <param name="tier">
    /// The tier serving it — <see cref="ModelTier.Cheap"/> under the shipped policy, since
    /// briefing is the routine turn SEC-31 routes away from the reasoning model. Recorded on
    /// the seed turn so the audit's cost breakdown can charge it to the right tier.
    /// </param>
    public OrchestratorExecutor(AIAgent agent, ModelTier tier = ModelTier.Cheap) : base(ExecutorId)
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));
        _tier = tier;
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

        if (_agent is not null)
        {
            var prompt = $"Briefing for Red Team:\n{message.Context}";
            var response = await _agent
                .RunAsync(prompt, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            content = response.Text ?? content;
            usage = DebateExecutor<DebateTurn>.UsageOf(response);
        }

        var seed = new DebateTurn
        {
            Role = AgentRole.Orchestrator, // round 0 carries the brief, not an assertion
            Round = 0,
            Content = content,
            Tier = _tier,
            Usage = usage
        };

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


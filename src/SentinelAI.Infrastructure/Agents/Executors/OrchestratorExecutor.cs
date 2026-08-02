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

    /// <summary>Creates a model-backed orchestrator that analyses the brief via NIM.</summary>
    public OrchestratorExecutor(AIAgent agent) : base(ExecutorId)
        => _agent = agent ?? throw new ArgumentNullException(nameof(agent));

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
        if (_agent is not null)
        {
            var prompt = $"Briefing for Red Team:\n{message.Context}";
            var response = await _agent
                .RunAsync(prompt, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            content = response.Text ?? content;
        }

        var seed = new DebateTurn
        {
            Role = AgentRole.Orchestrator, // round 0 carries the brief, not an assertion
            Round = 0,
            Content = content
        };

        // Round 0 seeds the state but is not itself a debate turn, so the transcript
        // starts empty and TurnCount counts only real agent turns.
        await context
            .QueueStateUpdateAsync(
                DebateStateKeys.State,
                new DebateState { Round = 0, ResourceGraph = message.Context },
                DebateStateKeys.SharedScope,
                cancellationToken)
            .ConfigureAwait(false);

        return seed;
    }
}


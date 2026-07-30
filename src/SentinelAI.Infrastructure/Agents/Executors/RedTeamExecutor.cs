using Microsoft.Agents.AI;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Agents.Executors;

/// <summary>
/// Asserts ordered cross-layer exploit paths within bounded candidates (AID-01 3.1).
/// Heads each debate round, so it is what increments the round counter.
/// </summary>
public sealed class RedTeamExecutor(AIAgent agent) : DebateExecutor(ExecutorId, agent, AgentRole.Red)
{
    /// <summary>Node id in the workflow graph. Named to avoid shadowing <c>Executor.Id</c>.</summary>
    public const string ExecutorId = "red-team";

    /// <summary>Instructions the backing <c>ChatClientAgent</c> is created with.</summary>
    public const string Instructions =
        """
        You are the Red Team agent in a security audit debate.
        Assert one ordered cross-layer exploit path using ONLY the edges present in the
        supplied resource graph. Never invent an edge. Cap the chain at 3-4 hops and seed
        it from the highest-severity finding. State each hop as node -> technique -> evidence.

        Answer directly. No preamble, no restating the task, no thinking aloud — begin with
        the chain itself and use one short line per hop.
        """;

    protected override string BuildPrompt(DebateTurn incoming, DebateState state) =>
        $"""
        {state.ResourceGraph}

        Round {incoming.Round + 1}.
        {Quote(incoming.Role, incoming.Content)}

        Assert the strongest 3-4 hop chain using ONLY the edges above.
        An edge Blue could not confirm is still an edge in the graph — you may assert it,
        and Blue will judge it. Do not refuse to answer because a join is unresolved.
        """;

    protected override DebateTurn Interpret(string content, DebateTurn incoming, DebateState state) =>
        new()
        {
            Role = AgentRole.Red,
            Round = incoming.Round + 1,
            Content = content,
            // Red asserts; it does not decide confidence. Blue downgrades on inspection.
            Confidence = JoinConfidence.Certain
        };
}

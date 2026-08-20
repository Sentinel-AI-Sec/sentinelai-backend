using Microsoft.Agents.AI;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Observability;

namespace SentinelAI.Infrastructure.Agents.Executors;

/// <summary>
/// Asserts ordered cross-layer exploit paths within bounded candidates (AID-01 3.1).
/// Heads each debate round, so it is what increments the round counter.
/// </summary>
public sealed class RedTeamExecutor(AIAgent agent, ModelTier tier = ModelTier.High, TurnTracing? tracing = null)
    : DebateExecutor(ExecutorId, agent, AgentRole.Red, tier, tracing)
{
    /// <summary>Node id in the workflow graph. Named to avoid shadowing <c>Executor.Id</c>.</summary>
    public const string ExecutorId = "red-team";

    /// <summary>Instructions the backing <c>ChatClientAgent</c> is created with.</summary>
    /// <remarks>
    /// The ATT&amp;CK paragraph is audit 42-A's. "State each hop as node -&gt; technique -&gt;
    /// evidence" never asked for a technique <em>id</em>, and live turns duly put the graph's own
    /// relation word in that slot — <c>N3:pkg:x -&gt; technique:used-by -&gt; evidence:N8</c>.
    /// The chain_hops table has had a technique_id column since the first migration and no run
    /// has ever filled it, so the dashboard renders an ATT&amp;CK link with nothing after the
    /// slash. Asking for the id is what makes it recoverable at all;
    /// <c>HopVerdictReader.ReadTechniques</c> is what keeps a recalled one out, which is why the
    /// instruction is scoped to the knowledge in this brief rather than to what the model knows.
    /// </remarks>
    public const string Instructions =
        """
        You are the Red Team agent in a security audit debate.
        Assert one ordered cross-layer exploit path using ONLY the edges present in the
        supplied resource graph. Never invent an edge. Cap the chain at 3-4 hops and seed
        it from the highest-severity finding. State each hop as node -> technique -> evidence.

        Where the knowledge supplied with this brief names an ATT&CK technique for a hop,
        put that id on the hop's line in MITRE's own form (T1078, or T1078.004). One id per
        hop at most. If the supplied knowledge names none, write none — an id you remember
        rather than read here is worth nothing to the reader and will be discarded.

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
            Confidence = Confidence.Certain
        };
}

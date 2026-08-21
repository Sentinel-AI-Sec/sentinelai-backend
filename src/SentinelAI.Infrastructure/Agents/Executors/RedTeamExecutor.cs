using Microsoft.Agents.AI;
using SentinelAI.Application.Debate;
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
    /// <para>
    /// The ATT&amp;CK paragraph is audit 42-A's. "State each hop as node -&gt; technique -&gt;
    /// evidence" never asked for a technique <em>id</em>, and live turns duly put the graph's own
    /// relation word in that slot — <c>N3:pkg:x -&gt; technique:used-by -&gt; evidence:N8</c>.
    /// The chain_hops table has had a technique_id column since the first migration and no run
    /// has ever filled it, so the dashboard renders an ATT&amp;CK link with nothing after the
    /// slash. Asking for the id is what makes it recoverable at all;
    /// <c>HopVerdictReader.ReadTechniques</c> is what keeps a recalled one out, which is why the
    /// instruction is scoped to the knowledge in this brief rather than to what the model knows.
    /// </para>
    /// <para>
    /// <b>The pipe-delimited hop line replaces the old three-arrow one.</b> "node -&gt; technique
    /// -&gt; evidence" put three unlike things in one arrow sequence, so a reader could not tell
    /// which arrow was the edge — and neither could the model, which is how the relation word
    /// ended up in the technique slot. Now exactly one arrow means "this edge", and everything
    /// else is a named field after a pipe. The two node references still straddle that arrow,
    /// which is all <c>EdgeAssertionValidator</c> and <c>HopVerdictReader</c> ever anchored on,
    /// so both keep working on turns written either way.
    /// </para>
    /// <para>
    /// The closing IMPACT line exists because the chain alone does not say what is lost. Every
    /// turn named nodes and no consequence, and a reader ranking three chains by severity had
    /// nothing to rank them on but the CVSS of the first hop.
    /// </para>
    /// </remarks>
    public const string Instructions =
        """
        You are the Red Team agent in a security audit debate.
        Assert one ordered cross-layer exploit path using ONLY the edges present in the
        supplied resource graph. Never invent an edge. Cap the chain at 3-4 hops and seed
        it from the highest-severity finding.

        Write each hop on its own line, in exactly this shape:
          HOP <n>: <from> -> <relation> -> <to> | <ATT&CK id or none> | <evidence>
        Use the graph's own N-labels for <from> and <to> (N1, N7), the graph's own relation
        word for <relation>, and for <evidence> name the finding id, file or config detail
        that makes the hop reachable — not a restatement of the two nodes.

        Where the knowledge supplied with this brief names an ATT&CK technique for a hop,
        put that id in the middle field in MITRE's own form (T1078, or T1078.004). One id per
        hop at most. If the supplied knowledge names none, write none — an id you remember
        rather than read here is worth nothing to the reader and will be discarded.

        Close with two lines and nothing after them:
          CHAIN: <the whole path as N? -> N? -> N?>
          IMPACT: <one clause on what an attacker gains at the end of it>

        Answer directly. No preamble, no restating the task, no thinking aloud, no markdown —
        begin with HOP 1.
        """;

    protected override string BuildPrompt(DebateTurn incoming, DebateState state) =>
        $"""
        {state.ResourceGraph}

        Round {incoming.Round + 1}.
        {Quote(incoming.Role, incoming.Content)}

        Assert the strongest 3-4 hop chain using ONLY the edges above.
        An edge Blue could not confirm is still an edge in the graph — you may assert it,
        and Blue will judge it. Do not refuse to answer because a join is unresolved.

        One HOP line per hop, then CHAIN and IMPACT. Nothing else.
        """;

    protected override DebateTurn Interpret(string content, DebateTurn incoming, DebateState state) =>
        new()
        {
            Role = AgentRole.Red,
            Round = incoming.Round + 1,
            // Cleaned on the way in, not on the way out to the screen: this text is quoted into
            // Blue's next prompt, persisted, and fact-checked line by line, and a <think> block
            // or a markdown fence reaching any of those is the same defect three times over.
            Content = TranscriptText.Clean(content),
            // Red asserts; it does not decide confidence. Blue downgrades on inspection.
            Confidence = Confidence.Certain
        };
}

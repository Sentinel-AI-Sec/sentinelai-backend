using System.Text;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Graph;

/// <summary>
/// Renders the typed findings and nodes into the prose block the debate reads
/// (<see cref="ScanBrief.Context"/>).
/// </summary>
/// <remarks>
/// <para>
/// This is the seam <c>docs/Graph_Integration.md</c> §2 describes: the debate consumes the
/// graph as prompt text, so something has to turn typed objects into that text. Putting it here
/// means <see cref="Domain.Models.DebateState"/> keeps holding a plain string — §3.2's warning
/// is that typed objects in checkpointed state break resume from existing checkpoints on any
/// schema change.
/// </para>
/// <para>
/// <b>Node ids are written verbatim.</b> They are already canonical, and re-spelling them for
/// readability is exactly how the brief came to say <c>iam-role:api-task-role</c> while the
/// real graph said <c>iam_role:</c> — the agents then assert chains whose node ids can never be
/// matched back. The brief tells the agents to use them as-is, for the same reason.
/// </para>
/// <para>
/// <b>Edges are rendered when there are any, and their absence is stated when there are not.</b>
/// Either way the policy is explicit, because an agent given a node list with no stated edge
/// policy will infer edges, and an inferred edge is a fabricated hop.
/// </para>
/// <para>
/// This used to say "Edges: none were extracted for this scan" unconditionally — true when it
/// was written, because the SEC-45 seeder produces nodes and no edges. It stayed true in the
/// text long after it stopped being true in the graph: SEC-17→SEC-19 build an infra spine and
/// three seams, and the committed fixture yields <b>68 edges</b>. Every one of them was hidden
/// from the agents, who were then told not to infer any — so Red was asked to assert a
/// cross-layer chain over a graph it had been shown no way to cross. The chain the whole sprint
/// is about was unreachable in the prompt while being perfectly present in the database.
/// </para>
/// </remarks>
public sealed class ScanBriefRenderer
{
    /// <param name="edges">
    /// The edges of the graph the nodes came from. Null or empty renders the explicit
    /// "none were extracted, do not infer one" policy; anything else is listed in full.
    /// </param>
    public ScanBrief Render(
        Guid scanJobId,
        IReadOnlyList<Finding> findings,
        IReadOnlyList<GraphNode> nodes,
        IReadOnlyList<string> knowledge,
        IReadOnlyList<GraphEdge>? edges = null)
    {
        var sb = new StringBuilder();

        sb.AppendLine("RESOURCE GRAPH");
        sb.AppendLine("Node ids are canonical: type:identifier, lower-case. Use them verbatim.");
        sb.AppendLine();

        sb.AppendLine("Findings:");
        if (findings.Count == 0)
            sb.AppendLine("  (none)");
        foreach (var (finding, index) in findings.Select((f, i) => (f, i + 1)))
        {
            var keys = string.Join(" ", new[] { finding.CweId, finding.CveId }.Where(k => k is not null));
            sb.Append("  F").Append(index).Append(": ").Append(finding.NodeRef)
              .Append(" severity-").Append(finding.Severity);

            if (keys.Length > 0) sb.Append(' ').Append(keys);

            sb.Append(" — ").AppendLine(OneLine(finding.Message));
        }

        sb.AppendLine();
        sb.Append("Nodes: ");
        sb.AppendLine(nodes.Count == 0
            ? "(none)"
            : string.Join(" | ", nodes.Select((n, i) => $"N{i + 1}={n.NodeKey}{(n.IsHot ? " HOT" : "")}")));

        sb.AppendLine();
        AppendEdges(sb, nodes, edges);

        if (knowledge.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Knowledge retrieved for these findings:");
            foreach (var chunk in knowledge)
                sb.Append("  - ").AppendLine(OneLine(chunk));
        }

        return new ScanBrief(scanJobId.ToString(), sb.ToString());
    }

    /// <summary>
    /// Writes the edge list, or the explicit no-edges policy when the graph has none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Edges are written as <c>N3 --used-by--> N7 (certain)</c>: the same N-indices the node
    /// line just defined, so the agents can read a path without re-matching node keys, and the
    /// confidence in brackets because AID-01 §3.3 makes the weakest join the whole chain's
    /// confidence — an agent that cannot see which join is weak cannot report it.
    /// </para>
    /// <para>
    /// An edge whose endpoints are not both in <paramref name="nodes"/> is skipped rather than
    /// written with a dangling reference. That should not happen — the writers persist both
    /// together — but a brief naming a node the node list does not contain is precisely the
    /// mismatch that makes an agent assert a chain nothing can match back.
    /// </para>
    /// </remarks>
    private static void AppendEdges(
        StringBuilder sb, IReadOnlyList<GraphNode> nodes, IReadOnlyList<GraphEdge>? edges)
    {
        if (edges is null || edges.Count == 0)
        {
            sb.AppendLine(
                "Edges: none were extracted for this scan. Do not infer one. A hop you cannot name "
                + "an edge for is not a hop.");
            return;
        }

        var labelById = nodes
            .Select((node, index) => (node.Id, Label: $"N{index + 1}"))
            .ToDictionary(entry => entry.Id, entry => entry.Label);

        var indexById = nodes
            .Select((node, index) => (node.Id, Index: index))
            .ToDictionary(entry => entry.Id, entry => entry.Index);

        sb.AppendLine("Edges (these are the only ones that exist — do not infer any other):");

        // Ordered by endpoint, not by insertion. Persistence order interleaves the handful of
        // cross-layer edges that make a chain possible with the dozens of dep→code edges that
        // all point at the same node — on the committed fixture, nine among fifty-nine. Sorted,
        // every edge out of a node is contiguous, so the path an agent has to find reads down
        // the page instead of being reassembled from scattered lines.
        var ordered = edges
            .Where(e => indexById.ContainsKey(e.FromNodeId) && indexById.ContainsKey(e.ToNodeId))
            .OrderBy(e => indexById[e.FromNodeId])
            .ThenBy(e => indexById[e.ToNodeId]);

        var written = 0;
        foreach (var edge in ordered)
        {
            sb.Append("  ").Append(labelById[edge.FromNodeId])
              .Append(" --").Append(edge.Relation).Append("--> ").Append(labelById[edge.ToNodeId])
              .Append(" (").Append(edge.Confidence.ToString().ToLowerInvariant()).AppendLine(")");
            written++;
        }

        if (written == 0)
            sb.AppendLine("  (none joined the nodes above)");

        sb.AppendLine(
            "A hop you cannot name an edge for is not a hop. A chain is no more confident than "
            + "its weakest edge.");
    }

    /// <summary>
    /// Flattens newlines. Scanner messages are multi-line (Trivy states the package, version
    /// and fixed version on separate lines) and a stray newline inside a numbered list turns
    /// one finding into what reads as several.
    /// </summary>
    private static string OneLine(string text) =>
        string.Join(" ", text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
}

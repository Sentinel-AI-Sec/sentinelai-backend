using System.Text;
using SentinelAI.Application.Features.Scan.Retrieval;
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
/// It renders no edges, because the seeded graph has none. Saying so explicitly matters: an
/// agent given a node list with no stated edge policy will infer edges, and an inferred edge is
/// a fabricated hop.
/// </para>
/// </remarks>
public sealed class ScanBriefRenderer
{
    /// <summary>
    /// Renders the brief, with each agent's knowledge under its own heading (SEC-23).
    /// </summary>
    /// <param name="knowledgeByRole">What each agent retrieved. Red's came from the offense
    /// collection and Blue's from defense, so they are labelled rather than merged — a mitigation
    /// listed among attacker knowledge reads to Red as a technique.</param>
    public ScanBrief Render(
        Guid scanJobId,
        IReadOnlyList<Finding> findings,
        IReadOnlyList<GraphNode> nodes,
        IReadOnlyDictionary<AgentRole, IReadOnlyList<string>> knowledgeByRole)
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
        sb.AppendLine(
            "Edges: none were extracted for this scan. Do not infer one. A hop you cannot name "
            + "an edge for is not a hop.");

        // One section per agent, named by the question it asked. Red must be able to tell its
        // own attacker knowledge from Blue's remediation guidance; a single merged list would
        // hand both agents the other's answers and quietly undo the offense/defense split.
        foreach (var role in AgentRetrieval.RetrievingRoles)
        {
            if (!knowledgeByRole.TryGetValue(role, out var chunks) || chunks.Count == 0) continue;

            sb.AppendLine();
            sb.Append("Knowledge retrieved for ").Append(role).Append(" (")
              .Append(AgentRetrieval.CollectionFor(role)!.Value.Wire()).AppendLine("):");

            foreach (var chunk in chunks)
                sb.Append("  - ").AppendLine(OneLine(chunk));
        }

        return new ScanBrief(scanJobId.ToString(), sb.ToString());
    }

    /// <summary>
    /// Flattens newlines. Scanner messages are multi-line (Trivy states the package, version
    /// and fixed version on separate lines) and a stray newline inside a numbered list turns
    /// one finding into what reads as several.
    /// </summary>
    private static string OneLine(string text) =>
        string.Join(" ", text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    /// <summary>
    /// Renders with one undifferentiated knowledge list, attributed to Red.
    /// </summary>
    /// <remarks>
    /// For callers that retrieve once rather than per agent. Attributed rather than left
    /// unlabelled because an unattributed block reads to both agents as theirs, which is the
    /// merge SEC-23 exists to undo.
    /// </remarks>
    public ScanBrief Render(
        Guid scanJobId,
        IReadOnlyList<Finding> findings,
        IReadOnlyList<GraphNode> nodes,
        IReadOnlyList<string> knowledge) =>
        Render(scanJobId, findings, nodes,
            new Dictionary<AgentRole, IReadOnlyList<string>> { [AgentRole.Red] = knowledge });
}

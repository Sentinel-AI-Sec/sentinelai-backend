using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Application.Features.Scan.Graph;

/// <summary>
/// The graph stage of the walking skeleton (SEC-45): turns the unified findings into the nodes
/// they decorate. One node per distinct <see cref="Finding.NodeRef"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is deliberately the thinnest graph that is still a graph — nodes only, no edges. Edges
/// come from the Terraform and code readers (SEC-17/SEC-18), and inventing them here would mean
/// inventing relationships no scanner reported. A node set with no edges is an honest empty
/// graph; a node set with guessed edges is a fabricated chain.
/// </para>
/// <para>
/// What it does prove, and what the skeleton exists to prove, is that the normalize → graph seam
/// closes: every finding's node reference parses as a canonical key, and the node built from it
/// carries that exact key back. If those two ever drift the graph splits into disconnected
/// islands, zero chains are found, and nothing errors (SEC-03).
/// </para>
/// </remarks>
public sealed class GraphSeeder
{
    /// <summary>
    /// A finding at or above this severity makes its node hot. 3 is "high"/"warning" on the
    /// normalized 0–4 scale, which is the level AID-01 seeds candidate chains from.
    /// </summary>
    public const int HotSeverity = 3;

    /// <summary>
    /// Builds the node set the findings decorate.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// A finding carries a node reference that <see cref="NodeId"/> could not have produced.
    /// Thrown rather than skipped: a finding that cannot join the graph is invisible to every
    /// stage after this one, and dropping it quietly is the silent failure this seam exists to
    /// catch.
    /// </exception>
    public IReadOnlyList<GraphNode> Seed(IEnumerable<Finding> findings, Guid tenantId, Guid scanJobId)
    {
        var nodes = new Dictionary<string, GraphNode>(StringComparer.Ordinal);

        foreach (var finding in findings)
        {
            // IsCanonical, not just TryParse. TryParse is lenient by design — it lower-cases
            // what it reads — so a hand-built "Code:OrderService" parses happily and then
            // yields the node key "code:orderservice", which the finding's own reference no
            // longer matches. That is the island bug arriving through the front door.
            if (!NodeId.IsCanonical(finding.NodeRef) ||
                !NodeId.TryParse(finding.NodeRef, out var nodeType, out var identifier))
            {
                throw new InvalidOperationException(
                    $"Finding {finding.Id} ({finding.SourceTool}/{finding.CheckId}) carries node reference "
                    + $"'{finding.NodeRef}', which is not a key NodeId could have produced. It could never "
                    + "join the graph.");
            }

            var isHot = finding.Severity >= HotSeverity;

            if (nodes.TryGetValue(finding.NodeRef, out var existing))
            {
                // One hot finding is enough to make the node hot; a later cool one must not
                // cool it back down.
                existing.IsHot |= isHot;
                continue;
            }

            // Create, not a constructor: the factory sets key and type together, so the key
            // this node is found by is the same string the finding referenced.
            nodes[finding.NodeRef] = GraphNode.Create(
                tenantId, scanJobId, nodeType, identifier, LayerOf(nodeType, finding), isHot);
        }

        return [.. nodes.Values];
    }

    /// <summary>
    /// The node's layer. Taken from the node type rather than from the finding, because the
    /// node outlives any one finding: two tools may report on one package from different
    /// layers, but the package is a dependency either way.
    /// </summary>
    private static Layer LayerOf(NodeType nodeType, Finding finding) => nodeType switch
    {
        NodeType.Pkg => Layer.Dep,
        NodeType.Code => Layer.Code,
        NodeType.Image or NodeType.Task or NodeType.IamRole or NodeType.Resource => Layer.Infra,
        _ => finding.Layer,
    };
}

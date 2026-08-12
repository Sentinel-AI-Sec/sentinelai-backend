using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-17: turns a bundle's Terraform graph inputs into the infra layer of the resource graph —
/// attacker-oriented nodes and edges, persisted by the Application layer as
/// <c>graph_nodes</c>/<c>graph_edges</c> with <c>seam = infra-spine</c>. This class is the
/// single entry point (<see cref="Read"/>); the five steps the ticket describes live as
/// follows:
/// <list type="number">
/// <item><b>Parse the DOT into raw nodes/edges</b> — <see cref="TerraformDotParser"/>. Literal
/// Terraform addresses, Terraform's own build-order edge direction, no canonical ids yet.</item>
/// <item><b>Re-orient edges to attack direction</b> — <see cref="AttackDirectionOrienter"/>.
/// Isolated on purpose: reversing this backwards is the "zero-chains failure mode" and needs
/// its own regression test independent of everything else in this pipeline.</item>
/// <item><b>Canonicalize + prepare for persistence</b> — this class, below: raw addresses become
/// <see cref="NodeId"/>-built <see cref="GraphNode"/>s via <see cref="TerraformResourceTypeMap"/>,
/// oriented edges become <see cref="InfraSpineEdge"/> DTOs (still keyed by node key, not by
/// database id — <c>InfraSpineWriter</c> in the Application layer resolves ids once the nodes
/// are actually persisted, and owns the upsert-on-(scan_job_id,node_key)-collision behavior the
/// ticket calls the "island bug").</item>
/// <item><b>HCL parse fallback</b> — <see cref="TerraformHclParser"/>, used by <see cref="Read"/>
/// below when the DOT input is missing/empty/unusable. See the trigger condition in
/// <see cref="Read"/> and the parser's own doc comment for what it does and doesn't cover.</item>
/// <item><b>Orientation regression guard</b> — lives with step 2:
/// <c>AttackDirectionOrienterTests</c> in the Infrastructure test project.</item>
/// </list>
/// </summary>
public sealed class TerraformInfraSpineReader(ILogger<TerraformInfraSpineReader> logger) : IInfraSpineReader
{
    /// <summary>
    /// The relation label for every edge this reader produces. Deliberately one constant
    /// rather than one per resource-type pair: every edge here means the same thing regardless
    /// of what the two endpoints are — "the attacker at <c>From</c> can reach <c>To</c>" — and
    /// that's exactly <c>can-access</c> in the SEC-03 relation vocabulary (Data_Contracts.md).
    /// </summary>
    private const string Relation = "can-access";

    public InfraSpineReadResult Read(InfraSpineInput input, Guid tenantId, Guid scanJobId)
    {
        var raw = TerraformDotParser.Parse(input.DotText);
        var usedHclFallback = false;

        // Trigger for the HCL fallback: no DOT text at all, or DOT text that parsed to zero
        // usable resource nodes (e.g. `terraform init` never ran on the runner, so `terraform
        // graph` either wasn't invoked or emitted nothing meaningful). Both are treated the
        // same way — "the good path produced nothing" — rather than trying to distinguish
        // "absent" from "present but empty/malformed", since the fallback response is identical
        // either way.
        if (raw.Nodes.Count == 0)
        {
            usedHclFallback = true;
            logger.LogWarning(
                "Terraform DOT graph for scan job {ScanJobId} produced no resource nodes; " +
                "falling back to HCL parsing of {FileCount} .tf file(s)",
                scanJobId, input.HclFiles.Count);
            raw = TerraformHclParser.Parse(input.HclFiles);
        }

        var orientedEdges = AttackDirectionOrienter.Reverse(raw.Edges);

        // Step 3: canonicalize. Every raw node either maps to a NodeType (kept) or doesn't
        // (dropped as noise — same treatment step 1 gives providers and module scaffolding,
        // just one layer up: TerraformResourceTypeMap's vocabulary, not DOT's).
        var nodesByKey = new Dictionary<string, GraphNode>(StringComparer.Ordinal);
        var nodeKeyByAddress = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var node in raw.Nodes)
        {
            if (!TerraformResourceTypeMap.TryMap(node.ResourceType, out var nodeType))
                continue;

            var nodeKey = NodeId.For(nodeType, node.Identifier);
            nodeKeyByAddress[node.Address] = nodeKey;

            if (nodesByKey.ContainsKey(nodeKey))
            {
                // Two different Terraform addresses normalized to the same canonical key —
                // e.g. two modules whose identifiers only differ by case. Keep the first,
                // warn loudly: this is two extractors (or two resources) disagreeing on what
                // one canonical id means, which is the island bug arriving before persistence
                // even gets a chance to catch it.
                logger.LogWarning(
                    "Terraform address {Address} normalized to node key {NodeKey}, which another " +
                    "resource in this same graph already produced for scan job {ScanJobId}; keeping " +
                    "the first and dropping this one",
                    node.Address, nodeKey, scanJobId);
                continue;
            }

            // Id assigned here, not left for EF/the database: InfraSpineWriter needs a real id
            // to build edges against before these nodes are ever saved (edges reference nodes
            // by database id, and this reader has no database access to round-trip through).
            var graphNode = GraphNode.Create(tenantId, scanJobId, nodeType, node.Identifier, Layer.Infra);
            graphNode.Id = Guid.CreateVersion7();
            nodesByKey[nodeKey] = graphNode;
        }

        var edges = new List<InfraSpineEdge>();
        var seenEdges = new HashSet<(string From, string To)>();

        foreach (var edge in orientedEdges)
        {
            // Only keep the edge if both endpoints survived canonicalization — an edge to/from
            // a resource type with no canonical home is exactly as unreal as an edge to/from a
            // provider node was in step 1.
            if (!nodeKeyByAddress.TryGetValue(edge.FromAddress, out var fromKey)) continue;
            if (!nodeKeyByAddress.TryGetValue(edge.ToAddress, out var toKey)) continue;
            if (!seenEdges.Add((fromKey, toKey))) continue;

            edges.Add(new InfraSpineEdge(fromKey, toKey, Relation, edge.OrientedAttackDir));
        }

        return new InfraSpineReadResult([.. nodesByKey.Values], edges, usedHclFallback);
    }
}

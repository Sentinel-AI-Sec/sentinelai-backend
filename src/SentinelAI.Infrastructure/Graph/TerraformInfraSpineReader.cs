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
/// <para>
/// One edge is not derived from the reversed graph: <c>task → role</c> (<c>assumes</c>), read
/// from the task definition's own role reference by <see cref="TaskDefinitionRoleExtractor"/>.
/// Added for SEC-20, which cannot reach the flagship chain's IAM hop without it — see
/// <see cref="BuildAssumesEdges"/> and that extractor's remarks. That relation <em>owns</em> the
/// task↔role direction: the reversal's mirror-image <c>role → task</c> edge is suppressed rather
/// than emitted alongside it, for the reason given on <see cref="BuildAssumesEdges"/>.
/// </para>
/// </summary>
public sealed class TerraformInfraSpineReader(ILogger<TerraformInfraSpineReader> logger) : IInfraSpineReader
{
    /// <summary>
    /// The relation label for every edge derived from the reversed dependency graph.
    /// Deliberately one constant rather than one per resource-type pair: every such edge means
    /// the same thing regardless of what the two endpoints are — "the attacker at <c>From</c>
    /// can reach <c>To</c>" — and that's exactly <c>can-access</c> in the SEC-03 relation
    /// vocabulary (Data_Contracts.md).
    /// </summary>
    private const string Relation = "can-access";

    /// <summary>
    /// The relation for the one edge this reader does <em>not</em> derive by reversal: a task
    /// definition assuming its IAM role. See <see cref="TaskDefinitionRoleExtractor"/> for why
    /// that edge is read from the reference itself rather than taken from the reversed graph, and
    /// <see cref="BuildAssumesEdges"/> for why it displaces the reversed edge instead of sitting
    /// beside it.
    /// </summary>
    private const string AssumesRelation = "assumes";

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

        // The assumes edges are built *before* the reversal edges rather than appended after,
        // because each one decides whether a reversal edge may exist at all: see
        // BuildAssumesEdges for the contradiction this ordering exists to prevent.
        var edges = BuildAssumesEdges(input.HclFiles, nodeKeyByAddress, scanJobId);
        var seenEdges = new HashSet<(string From, string To)>(edges.Select(e => (e.FromNodeKey, e.ToNodeKey)));
        var claimedByAssumes = new HashSet<(string From, string To)>(edges.Select(e => (e.ToNodeKey, e.FromNodeKey)));

        foreach (var edge in orientedEdges)
        {
            // Only keep the edge if both endpoints survived canonicalization — an edge to/from
            // a resource type with no canonical home is exactly as unreal as an edge to/from a
            // provider node was in step 1.
            if (!nodeKeyByAddress.TryGetValue(edge.FromAddress, out var fromKey)) continue;
            if (!nodeKeyByAddress.TryGetValue(edge.ToAddress, out var toKey)) continue;

            if (claimedByAssumes.Contains((fromKey, toKey)))
            {
                // Not a dropped signal — the same dependency, already recorded by the edge that
                // states its direction from the reference rather than by reversing it.
                logger.LogDebug(
                    "Dropping the reversal-derived edge {From} -> {To} for scan job {ScanJobId}: an " +
                    "assumes edge already owns this pair in the opposite direction",
                    fromKey, toKey, scanJobId);
                continue;
            }

            if (!seenEdges.Add((fromKey, toKey))) continue;

            edges.Add(new InfraSpineEdge(fromKey, toKey, Relation, edge.OrientedAttackDir));
        }

        return new InfraSpineReadResult([.. nodesByKey.Values], edges, usedHclFallback);
    }

    /// <summary>
    /// Builds a <c>task → role</c> <c>assumes</c> edge for every task definition that names an
    /// IAM role literally. These are the first edges in the returned list, and every pair one of
    /// them claims is closed to the reversal loop in <see cref="Read"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Runs on both the DOT and the HCL-fallback path, and reads the <c>.tf</c> source either
    /// way, because the DOT graph records that the dependency exists but not that it is a role
    /// attachment — and the direction only follows from knowing that. Nothing is added when the
    /// bundle carried no HCL, which is the same degraded-but-honest outcome the rest of this
    /// reader gives: fewer edges, never invented ones.
    /// </para>
    /// <para>
    /// <b>Why <c>assumes</c> owns the task↔role direction outright, and the reversal's mirror
    /// image is suppressed.</b> Both edges used to be emitted, on the argument that the reversal
    /// was left exactly as SEC-17 wrote it and the ATT&amp;CK tactic ordering in traversal would
    /// discard the backwards one. Measured on the real fixture that produced
    /// <c>iam_role:order_task_role --can-access--&gt; task:order_task</c> and
    /// <c>task:order_task --assumes--&gt; iam_role:order_task_role</c>, both
    /// <see cref="Confidence.Certain"/>, and the same pair again for <c>legacy_worker</c>. In a
    /// graph whose entire premise is that an edge encodes attack direction, two certain edges
    /// pointing opposite ways between one pair is not redundancy, it is the graph asserting a
    /// thing and its negation. Relying on a downstream filter to pick the right one means the
    /// contradiction is stored, exported, and true for every consumer that is not the traverser
    /// — and it makes a two-node cycle out of the one hop the flagship chain runs through.
    /// </para>
    /// <para>
    /// <c>assumes</c> is the survivor because it is the only one of the two that describes a
    /// move: compromise a task, assume the role it carries, act with that role's permissions.
    /// <c>role → task</c> is not a claim about attackers at all — it is the mechanical reversal
    /// of Terraform's "the task cannot be created before the role exists", a build-order fact
    /// that <see cref="AttackDirectionOrienter"/> flips because flipping is right for the
    /// resource pairs it was written against. Holding a role does not by itself put an attacker
    /// inside a task definition; something else has to run there first.
    /// </para>
    /// <para>
    /// The suppression is deliberately narrow: it removes only the exact mirror of an edge this
    /// method emitted, so a reversal edge with no <c>assumes</c> counterpart is untouched and the
    /// orienter's blanket reversal — and its standing regression test against the zero-chains bug
    /// — keeps working unchanged. <c>GraphEdgeContradictionTests</c> asserts the resulting
    /// invariant over the whole combined edge set, which is where the next such collision (from a
    /// seam that does not exist yet) would show up.
    /// </para>
    /// <para>
    /// Both endpoints are resolved through <paramref name="nodeKeyByAddress"/> rather than
    /// rebuilt with <see cref="NodeId"/>, so an edge is only emitted between nodes this reader
    /// really produced — and so a module-qualified address (which the HCL extractors cannot
    /// see) is skipped rather than joined to the wrong node key.
    /// </para>
    /// </remarks>
    private List<InfraSpineEdge> BuildAssumesEdges(
        IReadOnlyDictionary<string, string> hclFiles,
        IReadOnlyDictionary<string, string> nodeKeyByAddress,
        Guid scanJobId)
    {
        var edges = new List<InfraSpineEdge>();
        var seen = new HashSet<(string From, string To)>();
        var rolesByTaskDefinition = TaskDefinitionRoleExtractor.ExtractRoleNamesByTaskDefinitionName(hclFiles);

        foreach (var (taskName, roleNames) in rolesByTaskDefinition)
        {
            if (!nodeKeyByAddress.TryGetValue($"aws_ecs_task_definition.{taskName}", out var taskKey))
            {
                logger.LogWarning(
                    "Task definition {TaskName} names an IAM role but produced no canonical node " +
                    "for scan job {ScanJobId}; no assumes edge emitted",
                    taskName, scanJobId);
                continue;
            }

            foreach (var roleName in roleNames)
            {
                if (!nodeKeyByAddress.TryGetValue($"aws_iam_role.{roleName}", out var roleKey)) continue;
                if (!seen.Add((taskKey, roleKey))) continue;

                edges.Add(new InfraSpineEdge(taskKey, roleKey, AssumesRelation, OrientedAttackDir: true));
            }
        }

        return edges;
    }
}

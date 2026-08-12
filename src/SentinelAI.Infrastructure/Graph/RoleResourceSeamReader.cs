using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-18 part B: turns <see cref="TerraformIamPolicyParser"/>'s raw grants into the
/// role→resource seam — an <c>IamRole</c> node, one <c>can-access</c> edge per resource it can
/// reach, and (since this reader is standalone and may run before or independently of
/// <see cref="TerraformInfraSpineReader"/>) the target <c>Resource</c> nodes those edges point
/// to. The (scan_job_id, node_key) upsert at persistence time is what merges these back with
/// whichever nodes the infra spine already produced for the same role/resource, per this
/// project's "island bug" handling.
/// </summary>
public sealed class RoleResourceSeamReader : IRoleResourceSeamReader
{
    private const string Relation = "can-access";

    public RoleResourceSeamReadResult Read(RoleResourceSeamInput input, Guid tenantId, Guid scanJobId)
    {
        var grants = TerraformIamPolicyParser.ParseGrants(input.HclFiles);
        if (grants.Count == 0) return new RoleResourceSeamReadResult([], []);

        // Every declared resource this bundle's Terraform knows about, address-keyed — used both
        // to resolve a direct reference (role -> aws_s3_bucket.customer_data) and, filtered to
        // Resource-typed ones, as the candidate pool a wildcard grant widens across.
        var rawGraph = TerraformHclParser.Parse(input.HclFiles);
        var rawNodesByAddress = rawGraph.Nodes.ToDictionary(n => n.Address, StringComparer.Ordinal);
        var resourceTypedNodes = rawGraph.Nodes
            .Where(n => TerraformResourceTypeMap.TryMap(n.ResourceType, out var t) && t == NodeType.Resource)
            .ToList();

        var nodesByKey = new Dictionary<string, GraphNode>(StringComparer.Ordinal);
        var edges = new List<RoleResourceSeamEdge>();
        var seenEdges = new HashSet<(string From, string To)>();

        foreach (var grant in grants)
        {
            var roleNodeKey = NodeId.For(NodeType.IamRole, grant.RoleIdentifier);
            var roleNode = GetOrCreateNode(nodesByKey, roleNodeKey, NodeType.IamRole, grant.RoleIdentifier, tenantId, scanJobId);

            foreach (var target in grant.Targets)
            {
                var resolvedTargets = target.IsWildcard
                    ? ResolveWildcardTargets(target.ServicePrefix, resourceTypedNodes)
                    : ResolveDirectTarget(target.ResourceAddress!, rawNodesByAddress);

                foreach (var (nodeType, identifier) in resolvedTargets)
                {
                    var targetKey = NodeId.For(nodeType, identifier);
                    GetOrCreateNode(nodesByKey, targetKey, nodeType, identifier, tenantId, scanJobId);

                    if (!seenEdges.Add((roleNode.NodeKey, targetKey))) continue;
                    edges.Add(new RoleResourceSeamEdge(roleNode.NodeKey, targetKey, Relation, target.IsWildcard));
                }
            }
        }

        return new RoleResourceSeamReadResult([.. nodesByKey.Values], edges);
    }

    private static IEnumerable<(NodeType, string)> ResolveDirectTarget(
        string address, IReadOnlyDictionary<string, TerraformRawNode> rawNodesByAddress)
    {
        if (!rawNodesByAddress.TryGetValue(address, out var node)) yield break;
        if (!TerraformResourceTypeMap.TryMap(node.ResourceType, out var nodeType)) yield break;

        yield return (nodeType, node.Identifier);
    }

    private static IEnumerable<(NodeType, string)> ResolveWildcardTargets(
        string? servicePrefix, IReadOnlyList<TerraformRawNode> resourceTypedNodes)
    {
        var candidates = servicePrefix is null
            ? resourceTypedNodes
            : resourceTypedNodes.Where(n => n.ResourceType.StartsWith($"aws_{servicePrefix}_", StringComparison.OrdinalIgnoreCase));

        return candidates.Select(n => (NodeType.Resource, n.Identifier));
    }

    private static GraphNode GetOrCreateNode(
        Dictionary<string, GraphNode> nodesByKey, string nodeKey, NodeType nodeType, string identifier,
        Guid tenantId, Guid scanJobId)
    {
        if (nodesByKey.TryGetValue(nodeKey, out var existing)) return existing;

        var node = GraphNode.Create(tenantId, scanJobId, nodeType, identifier, Layer.Infra);
        node.Id = Guid.CreateVersion7();
        nodesByKey[nodeKey] = node;
        return node;
    }
}

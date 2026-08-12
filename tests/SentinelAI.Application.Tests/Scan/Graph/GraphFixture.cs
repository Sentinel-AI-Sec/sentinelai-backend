using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Tests.Scan.Graph;

/// <summary>
/// Builds small resource graphs for the SEC-20 tests.
/// </summary>
/// <remarks>
/// Nodes are built through <see cref="GraphNode.Create"/> rather than by object initializer so
/// the node keys in these tests are the same strings the real readers produce — a test graph
/// keyed by hand would happily pass while the production one splits into islands.
/// </remarks>
internal sealed class GraphFixture
{
    public static readonly Guid Tenant = Guid.NewGuid();
    public static readonly Guid Job = Guid.NewGuid();

    private readonly Dictionary<string, GraphNode> _nodes = new(StringComparer.Ordinal);
    private readonly List<GraphEdge> _edges = [];
    private readonly Dictionary<string, List<Finding>> _findings = new(StringComparer.Ordinal);

    public IReadOnlyList<GraphNode> Nodes => [.. _nodes.Values];
    public IReadOnlyList<GraphEdge> Edges => _edges;
    public IReadOnlyList<Finding> Findings => [.. _findings.Values.SelectMany(f => f)];

    public GraphNode this[string nodeKey] => _nodes[nodeKey];

    public GraphFixture Node(NodeType type, string identifier, bool hot = false)
    {
        var layer = type switch
        {
            NodeType.Pkg => Layer.Dep,
            NodeType.Code => Layer.Code,
            _ => Layer.Infra,
        };

        var node = GraphNode.Create(Tenant, Job, type, identifier, layer, hot);
        node.Id = Guid.NewGuid();
        _nodes[node.NodeKey] = node;

        return this;
    }

    public GraphFixture Edge(string fromKey, string toKey, string relation, Confidence confidence = Confidence.Certain)
    {
        _edges.Add(new GraphEdge
        {
            Id = Guid.NewGuid(),
            TenantId = Tenant,
            ScanJobId = Job,
            FromNodeId = _nodes[fromKey].Id,
            ToNodeId = _nodes[toKey].Id,
            Relation = relation,
            Seam = Seam.InfraSpine,
            Confidence = confidence,
            OrientedAttackDir = true,
        });

        return this;
    }

    /// <summary>Attaches a finding to a node and marks the node hot when it is severe enough.</summary>
    public GraphFixture Finding(string nodeKey, int severity, string message = "test finding")
    {
        var finding = new Finding
        {
            Id = Guid.NewGuid(),
            TenantId = Tenant,
            ScanJobId = Job,
            SourceTool = "test",
            Layer = _nodes[nodeKey].Layer,
            Severity = severity,
            NodeRef = nodeKey,
            Message = message,
        };

        if (!_findings.TryGetValue(nodeKey, out var list)) _findings[nodeKey] = list = [];
        list.Add(finding);

        if (severity >= 3) _nodes[nodeKey].IsHot = true;

        return this;
    }

    /// <summary>The decoration these findings imply, without going through the decorator.</summary>
    public DecoratedGraph Decoration() =>
        new(_findings.ToDictionary(
                e => e.Key,
                e => (IReadOnlyList<Finding>)[.. e.Value.OrderByDescending(f => f.Severity)],
                StringComparer.Ordinal),
            []);
}

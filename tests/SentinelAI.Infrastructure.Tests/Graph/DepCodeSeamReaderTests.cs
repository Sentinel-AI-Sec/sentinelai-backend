using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>
/// SEC-18 part A: package nodes, the project's provisional Code node, and the used-by edges
/// between them.
/// </summary>
public class DepCodeSeamReaderTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private readonly DepCodeSeamReader _reader = new(NullLogger<DepCodeSeamReader>.Instance);

    private const string LockFile = """
        {
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.3" },
              "Microsoft.Extensions.Logging.Abstractions": { "type": "Transitive", "resolved": "8.0.0" }
            }
          }
        }
        """;

    [Fact]
    public void Every_package_becomes_a_Pkg_node_with_its_version_in_attrs()
    {
        var result = _reader.Read(
            new DepCodeSeamInput("src/OrderService/packages.lock.json", LockFile), Tenant, Job);

        var pkg = Assert.Single(result.Nodes, n => n.NodeKey == NodeId.Package("Newtonsoft.Json"));
        Assert.Equal(NodeType.Pkg, pkg.NodeType);
        Assert.Equal(Layer.Dep, pkg.Layer);
        Assert.Contains("13.0.3", pkg.Attrs);
    }

    [Fact]
    public void Direct_and_transitive_packages_both_get_a_used_by_edge_to_the_code_node()
    {
        var result = _reader.Read(
            new DepCodeSeamInput("src/OrderService/packages.lock.json", LockFile), Tenant, Job);

        var codeKey = NodeId.Code("OrderService");
        Assert.Contains(result.Nodes, n => n.NodeKey == codeKey && n.NodeType == NodeType.Code);

        Assert.Equal(2, result.Edges.Count);
        Assert.Contains(result.Edges, e =>
            e.FromNodeKey == NodeId.Package("Newtonsoft.Json") && e.ToNodeKey == codeKey && e.Relation == "used-by");
        Assert.Contains(result.Edges, e =>
            e.FromNodeKey == NodeId.Package("Microsoft.Extensions.Logging.Abstractions") && e.ToNodeKey == codeKey);
    }

    [Fact]
    public void The_code_node_key_matches_this_projects_own_orderservice_convention()
    {
        // docs/Walking_Skeleton.md's own fixture uses NodeId.Code("OrderService") ->
        // code:orderservice — the provisional resolver must land on the exact same key from a
        // lock file path under that project's directory, or a real Roslyn finding on this same
        // project would never join to this Code node.
        var result = _reader.Read(
            new DepCodeSeamInput("src/OrderService/packages.lock.json", LockFile), Tenant, Job);

        Assert.Contains(result.Nodes, n => n.NodeKey == "code:orderservice");
    }

    [Fact]
    public void Unparseable_lock_file_produces_no_package_edges_but_does_not_throw()
    {
        var result = _reader.Read(
            new DepCodeSeamInput("src/OrderService/packages.lock.json", "not json"), Tenant, Job);

        Assert.Empty(result.Edges);
        Assert.Single(result.Nodes); // just the Code node
    }
}

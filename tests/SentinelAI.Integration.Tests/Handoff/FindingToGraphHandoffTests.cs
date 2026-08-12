using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Integration.Tests.Handoff;

/// <summary>
/// Boundary 1 — Findings → Graph. Does a finding's <see cref="Finding.NodeRef"/> resolve to a
/// real node in the built graph, and does a high-severity finding make that node hot?
/// </summary>
/// <remarks>
/// This is the boundary the whole ticket is named for. The join is a plain string match between
/// <see cref="Finding.NodeRef"/> and <see cref="GraphNode.NodeKey"/>; if they ever disagree the
/// finding is silently orphaned. The test asserts the exact key equality, not just "a node exists".
/// </remarks>
public class FindingToGraphHandoffTests
{
    private readonly GraphSeeder _graph = new();

    [Fact]
    public void A_findings_node_ref_resolves_to_a_real_node_with_the_same_key()
    {
        var finding = HandoffFixture.SeededFinding();

        var nodes = _graph.Seed([finding], HandoffFixture.Tenant, HandoffFixture.Job);

        // The node exists AND is found by the finding's own reference — the join, not just presence.
        var node = Assert.Single(nodes);
        Assert.Equal(finding.NodeRef, node.NodeKey);
        Assert.Equal("code:orderservice", node.NodeKey);

        // The key the node is found by round-trips to the type the node declares.
        Assert.True(NodeId.TryParse(node.NodeKey, out var parsedType, out _));
        Assert.Equal(node.NodeType, parsedType);
    }

    [Fact]
    public void A_high_severity_finding_marks_its_node_hot()
    {
        var node = Assert.Single(
            _graph.Seed([HandoffFixture.SeededFinding()], HandoffFixture.Tenant, HandoffFixture.Job));

        Assert.True(node.IsHot, "severity 4 is at or above the hot threshold and must mark the node hot");
    }

    [Fact]
    public void A_low_severity_finding_alone_leaves_its_node_cool()
    {
        var node = Assert.Single(
            _graph.Seed([HandoffFixture.LowSeverityFindingOnSameNode()], HandoffFixture.Tenant, HandoffFixture.Job));

        Assert.False(node.IsHot, "severity 1 is below the hot threshold");
    }

    [Fact]
    public void One_hot_finding_among_many_on_a_node_makes_the_node_hot()
    {
        // Two findings, one node: the join must collapse them onto a single node, and one hot
        // finding is enough — a later cool finding must not cool the node back down.
        var findings = new[] { HandoffFixture.LowSeverityFindingOnSameNode(), HandoffFixture.SeededFinding() };

        var node = Assert.Single(_graph.Seed(findings, HandoffFixture.Tenant, HandoffFixture.Job));

        Assert.Equal("code:orderservice", node.NodeKey);
        Assert.True(node.IsHot);
    }
}

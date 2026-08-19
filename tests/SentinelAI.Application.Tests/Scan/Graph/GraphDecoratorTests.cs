using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Application.Tests.Scan.Graph;

/// <summary>
/// The node-granularity join. Every test here uses node references spelled exactly the way
/// <c>FindingUnifier.BuildNodeRef</c> spells them and node keys spelled exactly the way the seam
/// readers spell them — the whole point is that those two spellings differ, so a test that
/// invented either would prove nothing.
/// </summary>
public class GraphDecoratorTests
{
    private static readonly GraphDecorator Decorator = new(NullLogger<GraphDecorator>.Instance);

    private static GraphNode Node(NodeType type, string identifier, Layer layer)
    {
        var node = GraphNode.Create(GraphFixture.Tenant, GraphFixture.Job, type, identifier, layer);
        node.Id = Guid.NewGuid();
        return node;
    }

    private static Finding Finding(Layer layer, string nodeRef, int severity = 4, string? location = null) =>
        new()
        {
            Id = Guid.NewGuid(),
            TenantId = GraphFixture.Tenant,
            ScanJobId = GraphFixture.Job,
            SourceTool = "test",
            Layer = layer,
            Severity = severity,
            NodeRef = nodeRef,
            Location = location,
            Message = "test finding",
        };

    /// <summary>
    /// OSV reports the exact version it found; the lock file's node is the package itself.
    /// <c>pkg:newtonsoft.json:12.0.1</c> and <c>pkg:newtonsoft.json</c> are the same package.
    /// </summary>
    [Fact]
    public void A_package_finding_attaches_to_the_package_node_despite_the_version()
    {
        var node = Node(NodeType.Pkg, "newtonsoft.json", Layer.Dep);
        var finding = Finding(Layer.Dep, NodeId.Package("newtonsoft.json:12.0.1"));

        var result = Decorator.Decorate([node], [finding]);

        Assert.Equal([finding], result.FindingsByNodeKey[node.NodeKey]);
        Assert.True(node.IsHot);
        Assert.Empty(result.Unattached);
    }

    /// <summary>
    /// Roslyn reports a file; <c>ProvisionalCodeNodeResolver</c> names the project directory.
    /// The file belongs to the project whose directory it sits under.
    /// </summary>
    [Fact]
    public void A_code_finding_attaches_to_the_project_that_owns_its_file()
    {
        var node = Node(NodeType.Code, "orderapp", Layer.Code);
        var finding = Finding(Layer.Code, NodeId.Code("src/orderapp/controllers/orderscontroller.cs"));

        var result = Decorator.Decorate([node], [finding]);

        Assert.Equal([finding], result.FindingsByNodeKey[node.NodeKey]);
        Assert.True(node.IsHot);
    }

    /// <summary>The deepest matching segment wins, so a nested project beats the tree it sits in.</summary>
    [Fact]
    public void The_innermost_project_claims_the_file()
    {
        var outer = Node(NodeType.Code, "src", Layer.Code);
        var inner = Node(NodeType.Code, "orderapp", Layer.Code);
        var finding = Finding(Layer.Code, NodeId.Code("src/orderapp/program.cs"));

        var result = Decorator.Decorate([outer, inner], [finding]);

        Assert.Equal([finding], result.FindingsByNodeKey[inner.NodeKey]);
        Assert.DoesNotContain(outer.NodeKey, result.FindingsByNodeKey.Keys);
    }

    /// <summary>
    /// A file named after some other project does not get claimed by it — only directory
    /// segments count.
    /// </summary>
    [Fact]
    public void A_files_own_name_does_not_claim_it_for_a_project()
    {
        var node = Node(NodeType.Code, "orderapp", Layer.Code);
        var finding = Finding(Layer.Code, NodeId.Code("src/billing/orderapp.cs"));

        var result = Decorator.Decorate([node], [finding]);

        Assert.Empty(result.FindingsByNodeKey);
        Assert.Equal([finding], result.Unattached);
        Assert.False(node.IsHot);
    }

    /// <summary>
    /// The infra half. Checkov reports <c>infra/iam.tf:25</c>; only the locator can say which
    /// Terraform resource that is, so the decorator takes its answer and checks it names a real
    /// node.
    /// </summary>
    [Fact]
    public void An_infra_finding_attaches_where_the_locator_places_it()
    {
        var role = Node(NodeType.IamRole, "order_task_role", Layer.Infra);
        var finding = Finding(Layer.Infra, NodeId.For(NodeType.Resource, "infra/iam.tf"), location: "infra/iam.tf:25");

        var result = Decorator.Decorate(
            [role], [finding], new Dictionary<string, string> { ["infra/iam.tf:25"] = role.NodeKey });

        Assert.Equal([finding], result.FindingsByNodeKey[role.NodeKey]);
        Assert.True(role.IsHot);
    }

    /// <summary>
    /// No Terraform in the bundle means infra findings stay file-grained. Unattached is the
    /// honest outcome — spreading them over whichever infra nodes exist would invent seeds.
    /// </summary>
    [Fact]
    public void An_infra_finding_the_locator_cannot_place_stays_unattached()
    {
        var role = Node(NodeType.IamRole, "order_task_role", Layer.Infra);
        var finding = Finding(Layer.Infra, NodeId.For(NodeType.Resource, "infra/iam.tf"), location: "infra/iam.tf:25");

        var result = Decorator.Decorate([role], [finding]);

        Assert.Empty(result.FindingsByNodeKey);
        Assert.Equal([finding], result.Unattached);
        Assert.False(role.IsHot);
    }

    /// <summary>A locator answer naming a node that does not exist is not trusted into being one.</summary>
    [Fact]
    public void A_locator_answer_for_a_node_that_does_not_exist_is_dropped()
    {
        var bucket = Node(NodeType.Resource, "customer_data", Layer.Infra);
        var finding = Finding(Layer.Infra, NodeId.For(NodeType.Resource, "infra/iam.tf"), location: "infra/iam.tf:25");

        var result = Decorator.Decorate(
            [bucket], [finding], new Dictionary<string, string> { ["infra/iam.tf:25"] = NodeId.Role("ghost") });

        Assert.Equal([finding], result.Unattached);
    }

    /// <summary>An already-agreeing reference needs no rule at all.</summary>
    [Fact]
    public void An_exact_match_attaches_directly()
    {
        var node = Node(NodeType.Code, "orderapp", Layer.Code);
        var finding = Finding(Layer.Code, node.NodeKey);

        var result = Decorator.Decorate([node], [finding]);

        Assert.Equal([finding], result.FindingsByNodeKey[node.NodeKey]);
    }

    /// <summary>
    /// The hot threshold is <see cref="GraphSeeder.HotSeverity"/>, shared with the SEC-16 node
    /// set so the two can never disagree about what seeds a chain.
    /// </summary>
    [Fact]
    public void Only_a_high_severity_finding_makes_a_node_hot()
    {
        var cool = Node(NodeType.Code, "coolproject", Layer.Code);
        var hot = Node(NodeType.Code, "hotproject", Layer.Code);

        Decorator.Decorate(
            [cool, hot],
            [
                Finding(Layer.Code, NodeId.Code("src/coolproject/a.cs"), GraphSeeder.HotSeverity - 1),
                Finding(Layer.Code, NodeId.Code("src/hotproject/b.cs"), GraphSeeder.HotSeverity),
            ]);

        Assert.False(cool.IsHot);
        Assert.True(hot.IsHot);
    }

    /// <summary>A later low-severity finding must not cool a node back down.</summary>
    [Fact]
    public void A_cool_finding_does_not_undo_a_hot_one()
    {
        var node = Node(NodeType.Code, "orderapp", Layer.Code);

        var result = Decorator.Decorate(
            [node],
            [
                Finding(Layer.Code, NodeId.Code("src/orderapp/a.cs"), severity: 4),
                Finding(Layer.Code, NodeId.Code("src/orderapp/b.cs"), severity: 1),
            ]);

        Assert.True(node.IsHot);
        Assert.Equal([4, 1], result.FindingsByNodeKey[node.NodeKey].Select(f => f.Severity).ToList());
    }
}

using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>
/// SEC-17 step 3: the single entry point wiring steps 1/2/4 together and canonicalizing the
/// result. Persistence (the upsert against the DB) is Application-layer
/// (<c>InfraSpineWriter</c>) and tested there — this covers what this reader alone is
/// responsible for: canonical NodeId mapping, dropping resource types with no canonical home,
/// in-batch node-key dedup, and the DOT-vs-HCL fallback trigger.
/// </summary>
public class TerraformInfraSpineReaderTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private readonly TerraformInfraSpineReader _reader =
        new(NullLogger<TerraformInfraSpineReader>.Instance);

    private const string FlagshipDot = """
        digraph G {
          "aws_ecs_task_definition.order_task" [label="aws_ecs_task_definition.order_task"];
          "aws_iam_role.order_task_role" [label="aws_iam_role.order_task_role"];
          "aws_security_group.order_svc_sg" [label="aws_security_group.order_svc_sg"];
          "aws_ecs_task_definition.order_task" -> "aws_iam_role.order_task_role";
          "aws_ecs_task_definition.order_task" -> "aws_security_group.order_svc_sg";
        }
        """;

    [Fact]
    public void Builds_canonical_nodes_using_the_real_NodeId_scheme()
    {
        var result = _reader.Read(new InfraSpineInput(FlagshipDot, HclFiles: new Dictionary<string, string>()), Tenant, Job);

        var role = Assert.Single(result.Nodes, n => n.NodeType == NodeType.IamRole);
        Assert.Equal(NodeId.For(NodeType.IamRole, "order_task_role"), role.NodeKey);
        Assert.Equal(Layer.Infra, role.Layer);
        Assert.False(role.IsHot);
        Assert.Equal(Tenant, role.TenantId);
        Assert.Equal(Job, role.ScanJobId);

        var task = Assert.Single(result.Nodes, n => n.NodeType == NodeType.Task);
        Assert.Equal(NodeId.For(NodeType.Task, "order_task"), task.NodeKey);
    }

    [Fact]
    public void Drops_resource_types_with_no_canonical_mapping_and_any_edge_touching_them()
    {
        var result = _reader.Read(new InfraSpineInput(FlagshipDot, HclFiles: new Dictionary<string, string>()), Tenant, Job);

        // aws_security_group has no NodeType mapping: no node, and the edge that touched it
        // is gone too.
        Assert.DoesNotContain(result.Nodes, n => n.NodeKey.StartsWith("security_group", StringComparison.Ordinal));
        Assert.Equal(2, result.Nodes.Count); // just the role and the task
        Assert.Single(result.Edges);
    }

    [Fact]
    public void Edges_are_reoriented_to_attack_direction_and_carry_the_infra_spine_relation()
    {
        var result = _reader.Read(new InfraSpineInput(FlagshipDot, HclFiles: new Dictionary<string, string>()), Tenant, Job);

        var edge = Assert.Single(result.Edges);
        Assert.Equal(NodeId.For(NodeType.IamRole, "order_task_role"), edge.FromNodeKey);
        Assert.Equal(NodeId.For(NodeType.Task, "order_task"), edge.ToNodeKey);
        Assert.True(edge.OrientedAttackDir);
    }

    [Fact]
    public void Two_addresses_normalizing_to_the_same_node_key_are_merged_not_duplicated()
    {
        // "Order_Task_Role" and "order_task_role" both normalize (NodeId lower-cases) to the
        // same canonical key — the in-batch flavor of the island bug.
        const string dot = """
            digraph G {
              "aws_iam_role.Order_Task_Role" [label="aws_iam_role.Order_Task_Role"];
              "aws_iam_role.order_task_role" [label="aws_iam_role.order_task_role"];
            }
            """;

        var result = _reader.Read(new InfraSpineInput(dot, HclFiles: new Dictionary<string, string>()), Tenant, Job);

        Assert.Single(result.Nodes);
    }

    [Fact]
    public void Missing_dot_falls_back_to_hcl_and_still_produces_the_flagship_nodes()
    {
        var hclFiles = new Dictionary<string, string>
        {
            ["infra/iam.tf"] = """
                resource "aws_iam_role" "order_task_role" {
                  name = "order-task-role"
                }
                """,
            ["infra/s3.tf"] = """
                resource "aws_s3_bucket" "customer_data" {
                  bucket = "sentinelai-fixture-customer-data"
                }
                """,
        };

        var result = _reader.Read(new InfraSpineInput(DotText: null, hclFiles), Tenant, Job);

        Assert.True(result.UsedHclFallback);
        Assert.Contains(result.Nodes, n => n.NodeKey == NodeId.For(NodeType.IamRole, "order_task_role"));
        Assert.Contains(result.Nodes, n => n.NodeKey == NodeId.For(NodeType.Resource, "customer_data"));
    }

    [Fact]
    public void Dot_that_parses_to_zero_nodes_also_triggers_the_hcl_fallback()
    {
        var hclFiles = new Dictionary<string, string>
        {
            ["infra/iam.tf"] = """
                resource "aws_iam_role" "order_task_role" {}
                """,
        };

        // Present, but not usable — same trigger as absent.
        var result = _reader.Read(new InfraSpineInput(DotText: "digraph G {}", hclFiles), Tenant, Job);

        Assert.True(result.UsedHclFallback);
        Assert.Single(result.Nodes);
    }

    [Fact]
    public void A_healthy_dot_never_touches_the_hcl_fallback()
    {
        var result = _reader.Read(
            new InfraSpineInput(FlagshipDot, HclFiles: new Dictionary<string, string> { ["infra/iam.tf"] = "garbage" }),
            Tenant, Job);

        Assert.False(result.UsedHclFallback);
    }
}

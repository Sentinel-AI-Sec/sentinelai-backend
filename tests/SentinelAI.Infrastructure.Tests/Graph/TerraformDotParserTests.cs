using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>
/// SEC-17 step 1. <see cref="RealFixtureDot"/> is trimmed from an actual
/// <c>terraform graph</c> run against the sentinelai-fixtures repo's flagship IAM/S3 scenario;
/// <see cref="NoisyDot"/> is hand-crafted to exercise noise-dropping and module qualification
/// that fixture doesn't happen to contain.
/// </summary>
public class TerraformDotParserTests
{
    private const string RealFixtureDot = """
        digraph G {
          rankdir = "RL";
          node [shape = rect, fontname = "sans-serif"];
          "aws_ecs_task_definition.order_task" [label="aws_ecs_task_definition.order_task"];
          "aws_iam_role.order_task_role" [label="aws_iam_role.order_task_role"];
          "aws_iam_role_policy.order_task_policy" [label="aws_iam_role_policy.order_task_policy"];
          "aws_s3_bucket.customer_data" [label="aws_s3_bucket.customer_data"];
          "aws_s3_bucket_public_access_block.customer_data_pab" [label="aws_s3_bucket_public_access_block.customer_data_pab"];
          "aws_ecs_task_definition.order_task" -> "aws_iam_role.order_task_role";
          "aws_iam_role_policy.order_task_policy" -> "aws_iam_role.order_task_role";
          "aws_s3_bucket_public_access_block.customer_data_pab" -> "aws_s3_bucket.customer_data";
        }
        """;

    private const string NoisyDot = """
        digraph G {
          "[root] aws_iam_role.order_task_role (expand)" [label="aws_iam_role.order_task_role"];
          "[root] module.storage.aws_s3_bucket.data (expand)" [label="module.storage.aws_s3_bucket.data"];
          "provider[\"registry.terraform.io/hashicorp/aws\"]" [label="provider"];
          "[root] aws_iam_role.order_task_role (expand)" -> "provider[\"registry.terraform.io/hashicorp/aws\"]";
          "[root] module.storage.aws_s3_bucket.data (expand)" -> "[root] aws_iam_role.order_task_role (expand)";
        }
        """;

    [Fact]
    public void Parses_resources_and_edges_dropping_noise()
    {
        var graph = TerraformDotParser.Parse(RealFixtureDot);

        // 5 declared node lines: order_task, order_task_role, order_task_policy, customer_data,
        // customer_data_pab. Step 1 has no notion of a canonical type vocabulary yet — that's
        // step 3's job — so aws_iam_role_policy and aws_s3_bucket_public_access_block, both
        // real resource-shaped addresses, are kept here even though neither has a canonical
        // NodeType.
        Assert.Equal(5, graph.Nodes.Count);
        Assert.Contains(graph.Nodes, n => n.Address == "aws_ecs_task_definition.order_task");
        Assert.Contains(graph.Nodes, n => n.Address == "aws_iam_role.order_task_role");
        Assert.Contains(graph.Nodes, n => n.Address == "aws_s3_bucket.customer_data");
        Assert.Contains(graph.Nodes, n => n.Address == "aws_iam_role_policy.order_task_policy");
        Assert.Contains(graph.Nodes, n => n.Address == "aws_s3_bucket_public_access_block.customer_data_pab");

        Assert.Equal(3, graph.Edges.Count);
        Assert.Contains(graph.Edges, e =>
            e.FromAddress == "aws_ecs_task_definition.order_task" && e.ToAddress == "aws_iam_role.order_task_role");
    }

    [Fact]
    public void Drops_root_prefix_and_operation_suffix_so_addresses_match_across_lines()
    {
        var graph = TerraformDotParser.Parse(NoisyDot);

        // "[root] aws_iam_role.order_task_role (expand)" must normalize to the same address
        // whether it appears as a node declaration or an edge endpoint.
        var role = Assert.Single(graph.Nodes, n => n.ResourceType == "aws_iam_role");
        Assert.Equal("aws_iam_role.order_task_role", role.Address);
    }

    [Fact]
    public void Tolerates_module_qualified_addresses()
    {
        var graph = TerraformDotParser.Parse(NoisyDot);

        var moduleNode = Assert.Single(graph.Nodes, n => n.ResourceType == "aws_s3_bucket");
        Assert.Equal("storage", moduleNode.ModulePath);
        Assert.Equal("data", moduleNode.ResourceName);
        Assert.Equal("storage.data", moduleNode.Identifier);
    }

    [Fact]
    public void Drops_provider_nodes_and_any_edge_touching_them()
    {
        var graph = TerraformDotParser.Parse(NoisyDot);

        Assert.DoesNotContain(graph.Nodes, n => n.ResourceType.Contains("provider", StringComparison.OrdinalIgnoreCase));
        // The role -> provider edge is dropped entirely (provider is not a resource node), but
        // the module bucket -> role edge, between two real resources, survives.
        Assert.Single(graph.Edges);
        Assert.Contains(graph.Edges, e =>
            e.FromAddress == "module.storage.aws_s3_bucket.data" && e.ToAddress == "aws_iam_role.order_task_role");
    }

    [Fact]
    public void Edge_is_dropped_if_either_endpoint_is_noise()
    {
        const string dot = """
            digraph G {
              "aws_iam_role.x" [label="aws_iam_role.x"];
              "aws_iam_role.x" -> "provider[\"registry.terraform.io/hashicorp/aws\"]";
              "data.aws_caller_identity.current" -> "aws_iam_role.x";
            }
            """;

        var graph = TerraformDotParser.Parse(dot);

        Assert.Empty(graph.Edges);
    }

    [Fact]
    public void Dedupes_nodes_and_edges_declared_more_than_once()
    {
        const string dot = """
            digraph G {
              "aws_iam_role.x" [label="aws_iam_role.x"];
              "aws_iam_role.x" [label="aws_iam_role.x"];
              "aws_ecs_task_definition.y" -> "aws_iam_role.x";
              "aws_ecs_task_definition.y" -> "aws_iam_role.x";
            }
            """;

        var graph = TerraformDotParser.Parse(dot);

        Assert.Equal(2, graph.Nodes.Count);
        Assert.Single(graph.Edges);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   \n  \n ")]
    [InlineData("this is not a dot file at all, just garbage text with no quotes")]
    public void Empty_or_malformed_input_yields_an_empty_graph_rather_than_throwing(string? dot)
    {
        var graph = TerraformDotParser.Parse(dot);

        Assert.Empty(graph.Nodes);
        Assert.Empty(graph.Edges);
    }
}

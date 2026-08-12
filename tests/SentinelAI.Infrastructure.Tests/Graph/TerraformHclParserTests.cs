using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>
/// SEC-17 step 4 — the degraded fallback used only when the DOT graph isn't available. Trimmed
/// from the same real fixture's <c>infra/iam.tf</c> and <c>infra/s3.tf</c>.
/// </summary>
public class TerraformHclParserTests
{
    private const string IamTf = """
        resource "aws_iam_role" "order_task_role" {
          name = "order-task-role"

          assume_role_policy = jsonencode({
            Version = "2012-10-17"
            Statement = [
              {
                Action = "sts:AssumeRole"
                Effect = "Allow"
              }
            ]
          })
        }

        resource "aws_iam_role_policy" "order_task_policy" {
          name = "order-task-s3-access"
          role = aws_iam_role.order_task_role.id

          policy = jsonencode({
            Statement = [
              { Effect = "Allow", Action = "s3:*", Resource = "*" }
            ]
          })
        }
        """;

    private const string MainTf = """
        resource "aws_ecs_task_definition" "order_task" {
          family             = "order-task"
          execution_role_arn = aws_iam_role.order_task_role.arn
          task_role_arn      = aws_iam_role.order_task_role.arn
        }
        """;

    private const string S3Tf = """
        resource "aws_s3_bucket" "customer_data" {
          bucket = "sentinelai-fixture-customer-data"
        }
        """;

    [Fact]
    public void Produces_iam_role_and_s3_bucket_nodes_from_resource_blocks()
    {
        var graph = TerraformHclParser.Parse(new Dictionary<string, string>
        {
            ["infra/iam.tf"] = IamTf,
            ["infra/main.tf"] = MainTf,
            ["infra/s3.tf"] = S3Tf,
        });

        Assert.Contains(graph.Nodes, n => n.ResourceType == "aws_iam_role" && n.ResourceName == "order_task_role");
        Assert.Contains(graph.Nodes, n => n.ResourceType == "aws_s3_bucket" && n.ResourceName == "customer_data");
    }

    [Fact]
    public void Finds_direct_attribute_references_across_files_as_edges()
    {
        var graph = TerraformHclParser.Parse(new Dictionary<string, string>
        {
            ["infra/iam.tf"] = IamTf,
            ["infra/main.tf"] = MainTf,
        });

        // order_task_role_policy references the role by role = aws_iam_role.order_task_role.id
        Assert.Contains(graph.Edges, e =>
            e.FromAddress == "aws_iam_role_policy.order_task_policy" && e.ToAddress == "aws_iam_role.order_task_role");

        // order_task (in a different file) references the role twice (execution + task role
        // arn) but that's one edge, not two.
        Assert.Single(graph.Edges, e =>
            e.FromAddress == "aws_ecs_task_definition.order_task" && e.ToAddress == "aws_iam_role.order_task_role");
    }

    [Fact]
    public void Ignores_variable_and_local_references_since_they_are_not_declared_resources()
    {
        const string tf = """
            resource "aws_ecs_task_definition" "legacy_worker_task" {
              container_definitions = jsonencode([{ image = var.legacy_worker_image }])
            }
            """;

        var graph = TerraformHclParser.Parse(new Dictionary<string, string> { ["infra/main.tf"] = tf });

        Assert.Single(graph.Nodes);
        Assert.Empty(graph.Edges);
    }

    [Fact]
    public void Empty_file_set_yields_an_empty_graph()
    {
        var graph = TerraformHclParser.Parse(new Dictionary<string, string>());

        Assert.Empty(graph.Nodes);
        Assert.Empty(graph.Edges);
    }
}

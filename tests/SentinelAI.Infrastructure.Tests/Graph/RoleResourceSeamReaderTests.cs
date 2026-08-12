using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>
/// SEC-18 part B: the full role→resource seam, from raw <c>.tf</c> source to canonical
/// <c>can-access</c> edges — including the flagship wildcard-widening case this project's
/// attack-chain demo depends on.
/// </summary>
public class RoleResourceSeamReaderTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private readonly RoleResourceSeamReader _reader = new();

    private const string IamTf = """
        resource "aws_iam_role" "order_task_role" {
          name = "order-task-role"
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

    private const string S3Tf = """
        resource "aws_s3_bucket" "customer_data" {
          bucket = "sentinelai-fixture-customer-data"
        }
        """;

    [Fact]
    public void Wildcard_policy_widens_to_the_real_bucket_declared_elsewhere_in_the_bundle()
    {
        var result = _reader.Read(
            new RoleResourceSeamInput(new Dictionary<string, string> { ["iam.tf"] = IamTf, ["s3.tf"] = S3Tf }),
            Tenant, Job);

        var edge = Assert.Single(result.Edges);
        Assert.Equal(NodeId.Role("order_task_role"), edge.FromNodeKey);
        Assert.Equal(NodeId.Resource("customer_data"), edge.ToNodeKey);
        Assert.Equal("can-access", edge.Relation);
        Assert.True(edge.Widened);
    }

    [Fact]
    public void Widening_never_reaches_a_resource_type_with_no_canonical_mapping()
    {
        const string dynamoTf = """
            resource "aws_dynamodb_table" "unrelated_table" {
              name = "unrelated"
            }
            """;

        var result = _reader.Read(
            new RoleResourceSeamInput(new Dictionary<string, string> { ["iam.tf"] = IamTf, ["s3.tf"] = S3Tf, ["dynamo.tf"] = dynamoTf }),
            Tenant, Job);

        // aws_dynamodb_table has no canonical NodeType mapping (only aws_s3_bucket maps to
        // Resource today), same noise treatment TerraformInfraSpineReader gives it — so a
        // wildcard widen never manufactures a node or edge for it.
        Assert.Single(result.Edges);
        Assert.DoesNotContain(result.Nodes, n => n.NodeKey.Contains("unrelated"));
    }

    [Fact]
    public void Produces_the_role_node_using_the_real_NodeId_scheme()
    {
        var result = _reader.Read(
            new RoleResourceSeamInput(new Dictionary<string, string> { ["iam.tf"] = IamTf, ["s3.tf"] = S3Tf }),
            Tenant, Job);

        var role = Assert.Single(result.Nodes, n => n.NodeType == NodeType.IamRole);
        Assert.Equal(NodeId.Role("order_task_role"), role.NodeKey);
        Assert.Equal(Layer.Infra, role.Layer);
        Assert.Equal(Tenant, role.TenantId);
        Assert.Equal(Job, role.ScanJobId);
    }

    [Fact]
    public void A_direct_reference_produces_a_non_widened_edge()
    {
        const string tf = """
            resource "aws_iam_role" "reporting_role" {
              name = "reporting-role"

              inline_policy {
                name = "reporting-s3-read"
                policy = jsonencode({
                  Statement = [
                    { Effect = "Allow", Action = "s3:GetObject", Resource = aws_s3_bucket.customer_data.arn }
                  ]
                })
              }
            }
            """;

        var result = _reader.Read(
            new RoleResourceSeamInput(new Dictionary<string, string> { ["iam.tf"] = tf, ["s3.tf"] = S3Tf }),
            Tenant, Job);

        var edge = Assert.Single(result.Edges);
        Assert.False(edge.Widened);
        Assert.Equal(NodeId.Resource("customer_data"), edge.ToNodeKey);
    }

    [Fact]
    public void No_grants_yields_an_empty_result()
    {
        var result = _reader.Read(new RoleResourceSeamInput(new Dictionary<string, string>()), Tenant, Job);

        Assert.Empty(result.Nodes);
        Assert.Empty(result.Edges);
    }
}

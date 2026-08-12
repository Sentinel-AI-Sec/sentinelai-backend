using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>
/// SEC-20's half of the node-granularity fix: turning "Checkov complained at
/// <c>infra/iam.tf:25</c>" into "this finding is about <c>iam_role:order_task_role</c>".
/// </summary>
/// <remarks>
/// The Terraform below is the committed fixture's <c>infra/iam.tf</c> and <c>infra/main.tf</c>,
/// trimmed to the blocks these tests exercise but with line-relevant structure and the real
/// resource names intact — a rewritten fixture would let a wrong line-to-block mapping pass.
/// </remarks>
public class TerraformFindingLocatorTests
{
    private readonly TerraformFindingLocator _locator = new(NullLogger<TerraformFindingLocator>.Instance);

    private const string IamTf = """
        resource "aws_iam_role" "order_task_role" {
          name = "order-task-role"

          assume_role_policy = jsonencode({
            Version = "2012-10-17"
            Statement = [
              {
                Effect    = "Allow"
                Principal = { Service = "ecs-tasks.amazonaws.com" }
                Action    = "sts:AssumeRole"
              }
            ]
          })
        }

        resource "aws_iam_role_policy" "order_task_policy" {
          name = "order-task-s3-access"
          role = aws_iam_role.order_task_role.id

          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [
              {
                Effect   = "Allow"
                Action   = "s3:*"
                Resource = "*"
              }
            ]
          })
        }
        """;

    private const string MainTf = """
        resource "aws_ecs_task_definition" "order_task" {
          family             = "order-task"
          task_role_arn      = aws_iam_role.order_task_role.arn

          container_definitions = jsonencode([
            { name = "order-service", image = "registry.hub.docker.com/tinyapp/order:1.4.2" }
          ])
        }
        """;

    private const string S3Tf = """
        resource "aws_s3_bucket" "customer_data" {
          bucket = "customer-data-bucket"
        }

        resource "aws_s3_bucket_versioning" "customer_data_versioning" {
          bucket = aws_s3_bucket.customer_data.id

          versioning_configuration {
            status = "Disabled"
          }
        }
        """;

    private static Dictionary<string, string> Bundle() => new()
    {
        ["graph-inputs/infra/iam.tf"] = IamTf,
        ["graph-inputs/infra/main.tf"] = MainTf,
        ["graph-inputs/infra/s3.tf"] = S3Tf,
    };

    /// <summary>A line inside a block whose resource type has a canonical node type.</summary>
    [Fact]
    public void A_finding_inside_a_mapped_resource_lands_on_that_resource()
    {
        // Line 2 is inside `resource "aws_ecs_task_definition" "order_task"`.
        var resolved = _locator.Locate(Bundle(), ["infra/main.tf:2"]);

        Assert.Equal(NodeId.Task("order_task"), resolved["infra/main.tf:2"]);
    }

    /// <summary>
    /// The flagship case. Checkov's CKV_AWS_290/289/288 all land on the policy block, which has
    /// no canonical node type — but the policy exists to configure a role it names literally,
    /// so the finding is about that role. This is what makes <c>iam_role:order_task_role</c> hot
    /// and therefore a chain seed.
    /// </summary>
    [Fact]
    public void A_finding_on_a_policy_lands_on_the_role_the_policy_configures()
    {
        // Line 20 is inside `resource "aws_iam_role_policy" "order_task_policy"`.
        var resolved = _locator.Locate(Bundle(), ["infra/iam.tf:20"]);

        Assert.Equal(NodeId.Role("order_task_role"), resolved["infra/iam.tf:20"]);
    }

    /// <summary>Same rule for S3 sub-resources: the versioning block is about the bucket.</summary>
    [Fact]
    public void A_finding_on_a_bucket_sub_resource_lands_on_the_bucket()
    {
        var resolved = _locator.Locate(Bundle(), ["infra/s3.tf:8"]);

        Assert.Equal(NodeId.Resource("customer_data"), resolved["infra/s3.tf:8"]);
    }

    /// <summary>The role block itself, not the policy — the direct path still works.</summary>
    [Fact]
    public void A_finding_on_the_role_block_lands_on_the_role()
    {
        var resolved = _locator.Locate(Bundle(), ["infra/iam.tf:2"]);

        Assert.Equal(NodeId.Role("order_task_role"), resolved["infra/iam.tf:2"]);
    }

    /// <summary>
    /// The bundle stores <c>graph-inputs/infra/iam.tf</c>; Checkov reported <c>infra/iam.tf</c>.
    /// Neither is wrong about its own root, so matching is by suffix.
    /// </summary>
    [Fact]
    public void A_repo_relative_finding_path_matches_a_bundle_relative_file()
    {
        var resolved = _locator.Locate(
            new Dictionary<string, string> { ["deep/nested/graph-inputs/infra/iam.tf"] = IamTf },
            ["infra/iam.tf:20"]);

        Assert.Equal(NodeId.Role("order_task_role"), resolved["infra/iam.tf:20"]);
    }

    /// <summary>A line between blocks belongs to no resource, and is not guessed at.</summary>
    [Fact]
    public void A_line_outside_every_block_resolves_to_nothing()
    {
        // Line 15 is the blank line between the two blocks in iam.tf.
        Assert.Empty(_locator.Locate(Bundle(), ["infra/iam.tf:15"]));
    }

    /// <summary>
    /// A finding with no line can only be attributed when the file leaves no choice. Guessing
    /// between two resources would invent a seed, and every chain grown from an invented seed is
    /// fiction.
    /// </summary>
    [Fact]
    public void A_finding_with_no_line_resolves_only_when_the_file_has_one_mapped_resource()
    {
        Assert.Equal(NodeId.Task("order_task"), _locator.Locate(Bundle(), ["infra/main.tf"])["infra/main.tf"]);

        // s3.tf declares a bucket and a versioning block; only the bucket is mappable, so it is
        // still unambiguous. iam.tf declares a role and a policy — same shape, one mappable.
        Assert.Equal(NodeId.Resource("customer_data"), _locator.Locate(Bundle(), ["infra/s3.tf"])["infra/s3.tf"]);

        var twoRoles = new Dictionary<string, string>
        {
            ["infra/iam.tf"] = """
                resource "aws_iam_role" "a" { name = "a" }
                resource "aws_iam_role" "b" { name = "b" }
                """,
        };

        Assert.Empty(_locator.Locate(twoRoles, ["infra/iam.tf"]));
    }

    [Fact]
    public void A_finding_in_a_file_the_bundle_does_not_have_resolves_to_nothing()
    {
        Assert.Empty(_locator.Locate(Bundle(), ["infra/network.tf:4"]));
    }

    [Fact]
    public void No_terraform_at_all_resolves_nothing_rather_than_throwing()
    {
        Assert.Empty(_locator.Locate(new Dictionary<string, string>(), ["infra/iam.tf:20"]));
    }

    /// <summary>
    /// A sub-resource that references nothing mappable stays unresolved — the security group in
    /// the fixture has no canonical node type and configures nothing that does.
    /// </summary>
    [Fact]
    public void An_unmapped_block_that_configures_nothing_mapped_resolves_to_nothing()
    {
        var files = new Dictionary<string, string>
        {
            ["infra/net.tf"] = """
                resource "aws_security_group" "order_svc_sg" {
                  name = "order-svc-sg"
                }
                """,
        };

        Assert.Empty(_locator.Locate(files, ["infra/net.tf:2"]));
    }

    /// <summary>
    /// Every key this class produces has to be one <see cref="NodeId"/> could have produced, or
    /// the finding attaches to a node that does not exist.
    /// </summary>
    [Fact]
    public void Every_resolved_key_is_canonical()
    {
        var resolved = _locator.Locate(Bundle(), ["infra/iam.tf:20", "infra/main.tf:2", "infra/s3.tf:8"]);

        Assert.Equal(3, resolved.Count);
        Assert.All(resolved.Values, key => Assert.True(NodeId.IsCanonical(key)));
    }

    /// <summary>The type map is what decides "mapped"; this pins the three types in play.</summary>
    [Fact]
    public void The_mapped_types_are_the_ones_the_chain_walks()
    {
        var resolved = _locator.Locate(Bundle(), ["infra/iam.tf:2", "infra/main.tf:2", "infra/s3.tf:2"]);

        Assert.Equal(
            [NodeType.IamRole, NodeType.Task, NodeType.Resource],
            resolved.Values.Select(k => { NodeId.TryParse(k, out var t, out _); return t; }).ToList());
    }
}

using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>
/// SEC-18 part B, step 1: reading role→resource grants out of the three Terraform IAM policy
/// shapes — inline, standalone, and managed-attachment — and the wildcard-widening decision.
/// </summary>
public class TerraformIamPolicyParserTests
{
    /// <summary>The flagship fixture: an over-permissioned role's standalone policy, wildcarded
    /// on both resource and action — the exact shape this project's attack-chain demo depends
    /// on being widened, not dropped.</summary>
    private const string WildcardPolicyTf = """
        resource "aws_iam_role" "order_task_role" {
          name = "order-task-role"

          assume_role_policy = jsonencode({
            Statement = [
              { Effect = "Allow", Action = "sts:AssumeRole" }
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

    [Fact]
    public void Standalone_policy_with_a_full_wildcard_widens_scoped_to_the_actions_service()
    {
        var grants = TerraformIamPolicyParser.ParseGrants(new Dictionary<string, string> { ["iam.tf"] = WildcardPolicyTf });

        var grant = Assert.Single(grants);
        Assert.Equal("order_task_role", grant.RoleIdentifier);

        var target = Assert.Single(grant.Targets);
        Assert.True(target.IsWildcard);
        Assert.Null(target.ResourceAddress);
        Assert.Equal("s3", target.ServicePrefix);
    }

    [Fact]
    public void The_trust_statements_own_assume_role_policy_grants_nothing()
    {
        // assume_role_policy lives directly on aws_iam_role, not inside an inline_policy block
        // — it says who may assume the role, not what the role can reach — so it must never be
        // read as a grant, wildcard or otherwise.
        var grants = TerraformIamPolicyParser.ParseGrants(new Dictionary<string, string> { ["iam.tf"] = WildcardPolicyTf });

        Assert.DoesNotContain(grants, g => g.RoleIdentifier == "order_task_role" && g.Targets.Count > 1);
    }

    [Fact]
    public void A_statement_with_no_Resource_field_grants_nothing()
    {
        const string tf = """
            resource "aws_iam_role_policy" "order_task_policy" {
              name = "order-task-malformed"
              role = aws_iam_role.order_task_role.id

              policy = jsonencode({
                Statement = [
                  { Effect = "Allow", Action = "sts:AssumeRole" }
                ]
              })
            }
            """;

        var grants = TerraformIamPolicyParser.ParseGrants(new Dictionary<string, string> { ["iam.tf"] = tf });

        Assert.Empty(grants);
    }

    [Fact]
    public void Inline_policy_inside_aws_iam_role_with_a_direct_reference_resolves_to_that_address()
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

        var grants = TerraformIamPolicyParser.ParseGrants(new Dictionary<string, string> { ["iam.tf"] = tf });

        var grant = Assert.Single(grants);
        Assert.Equal("reporting_role", grant.RoleIdentifier);

        var target = Assert.Single(grant.Targets);
        Assert.False(target.IsWildcard);
        Assert.Equal("aws_s3_bucket.customer_data", target.ResourceAddress);
    }

    [Fact]
    public void Managed_policy_attachment_widens_using_the_recognized_service_hint()
    {
        const string tf = """
            resource "aws_iam_role_policy_attachment" "order_task_s3_ro" {
              role       = aws_iam_role.order_task_role.name
              policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
            }
            """;

        var grants = TerraformIamPolicyParser.ParseGrants(new Dictionary<string, string> { ["iam.tf"] = tf });

        var grant = Assert.Single(grants);
        Assert.Equal("order_task_role", grant.RoleIdentifier);

        var target = Assert.Single(grant.Targets);
        Assert.True(target.IsWildcard);
        Assert.Equal("s3", target.ServicePrefix);
    }

    [Fact]
    public void Managed_policy_attachment_with_an_unrecognized_policy_name_still_widens_but_unscoped()
    {
        const string tf = """
            resource "aws_iam_role_policy_attachment" "order_task_admin" {
              role       = aws_iam_role.order_task_role.name
              policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
            }
            """;

        var grants = TerraformIamPolicyParser.ParseGrants(new Dictionary<string, string> { ["iam.tf"] = tf });

        var target = Assert.Single(Assert.Single(grants).Targets);
        Assert.True(target.IsWildcard);
        Assert.Null(target.ServicePrefix); // could not recognize the policy — widen unscoped, don't guess wrong
    }

    [Fact]
    public void Deny_statements_grant_nothing()
    {
        const string tf = """
            resource "aws_iam_role_policy" "order_task_policy" {
              name = "order-task-explicit-deny"
              role = aws_iam_role.order_task_role.id

              policy = jsonencode({
                Statement = [
                  { Effect = "Deny", Action = "s3:*", Resource = "*" }
                ]
              })
            }
            """;

        var grants = TerraformIamPolicyParser.ParseGrants(new Dictionary<string, string> { ["iam.tf"] = tf });

        Assert.Empty(grants);
    }

    [Fact]
    public void A_hardcoded_ARN_with_no_wildcard_signal_and_no_declared_resource_grants_nothing()
    {
        const string tf = """
            resource "aws_iam_role_policy" "order_task_policy" {
              name = "order-task-external-bucket"
              role = aws_iam_role.order_task_role.id

              policy = jsonencode({
                Statement = [
                  { Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::some-other-teams-bucket" }
                ]
              })
            }
            """;

        var grants = TerraformIamPolicyParser.ParseGrants(new Dictionary<string, string> { ["iam.tf"] = tf });

        Assert.Empty(grants);
    }

    [Fact]
    public void Empty_file_set_yields_no_grants()
    {
        Assert.Empty(TerraformIamPolicyParser.ParseGrants(new Dictionary<string, string>()));
    }
}

using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>
/// The <c>assumes</c> edge's source. Reading the role reference out of the task definition is
/// what lets the infra spine emit that edge pointing the way an attacker moves, instead of the
/// way the blanket dependency reversal points it.
/// </summary>
public class TaskDefinitionRoleExtractorTests
{
    private const string FixtureTf = """
        resource "aws_ecs_task_definition" "order_task" {
          family             = "order-task"
          execution_role_arn = aws_iam_role.order_task_role.arn
          task_role_arn      = aws_iam_role.order_task_role.arn

          container_definitions = jsonencode([
            { name = "order-service", image = "tinyapp/order:1.4.2" }
          ])
        }

        resource "aws_ecs_task_definition" "legacy_worker_task" {
          family        = "legacy-worker-task"
          task_role_arn = aws_iam_role.legacy_worker_role.arn
        }
        """;

    [Fact]
    public void Reads_the_role_each_task_definition_attaches()
    {
        var roles = TaskDefinitionRoleExtractor.ExtractRoleNamesByTaskDefinitionName(
            new Dictionary<string, string> { ["main.tf"] = FixtureTf });

        Assert.Equal(["legacy_worker_task", "order_task"], roles.Keys.Order().ToList());
        Assert.Equal(["legacy_worker_role"], roles["legacy_worker_task"]);
    }

    /// <summary>
    /// The fixture sets execution and task role to the same role. One edge, not two — a
    /// duplicated hop would inflate the chain and say nothing extra.
    /// </summary>
    [Fact]
    public void One_role_named_twice_is_one_role()
    {
        var roles = TaskDefinitionRoleExtractor.ExtractRoleNamesByTaskDefinitionName(
            new Dictionary<string, string> { ["main.tf"] = FixtureTf });

        Assert.Equal(["order_task_role"], roles["order_task"]);
    }

    [Fact]
    public void Distinct_execution_and_task_roles_are_both_kept()
    {
        const string tf = """
            resource "aws_ecs_task_definition" "order_task" {
              execution_role_arn = aws_iam_role.ecs_execution_role.arn
              task_role_arn      = aws_iam_role.order_task_role.arn
            }
            """;

        var roles = TaskDefinitionRoleExtractor.ExtractRoleNamesByTaskDefinitionName(
            new Dictionary<string, string> { ["main.tf"] = tf });

        Assert.Equal(["ecs_execution_role", "order_task_role"], roles["order_task"].Order().ToList());
    }

    /// <summary>
    /// A role ARN built from a variable is not a literal reference, so it is invisible here —
    /// exactly as it is invisible to Terraform's own literal-reference edges. Absent, not
    /// guessed.
    /// </summary>
    [Fact]
    public void A_non_literal_role_reference_is_not_invented()
    {
        const string tf = """
            resource "aws_ecs_task_definition" "order_task" {
              task_role_arn = var.task_role_arn
            }
            """;

        Assert.Empty(TaskDefinitionRoleExtractor.ExtractRoleNamesByTaskDefinitionName(
            new Dictionary<string, string> { ["main.tf"] = tf }));
    }

    [Fact]
    public void No_terraform_yields_nothing()
    {
        Assert.Empty(TaskDefinitionRoleExtractor.ExtractRoleNamesByTaskDefinitionName(
            new Dictionary<string, string>()));
    }
}

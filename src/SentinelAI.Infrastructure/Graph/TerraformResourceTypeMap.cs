using SentinelAI.Domain.Enums;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// Maps a Terraform resource type (e.g. <c>aws_iam_role</c>) to the canonical
/// <see cref="NodeType"/> it becomes in the graph. <see cref="NodeType"/> is a closed, small
/// vocabulary (SEC-03) that this ticket does not get to extend, so most Terraform resource
/// types have no entry here on purpose — see <see cref="TryMap"/>.
/// </summary>
/// <remarks>
/// This is the extension point the ticket asks for: a resource type with no attacker-relevant
/// canonical type yet (a security group, an inline IAM policy document, an S3 sub-resource like
/// versioning or a public-access block, ...) is not noise in the Terraform sense — Terraform
/// still models it — but it is noise for <em>this</em> graph until a canonical type for it
/// exists. Adding one is a two-line change: a new <see cref="NodeType"/> member (a SEC-03
/// decision, not this ticket's) and a new entry below.
/// </remarks>
internal static class TerraformResourceTypeMap
{
    private static readonly Dictionary<string, NodeType> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        ["aws_iam_role"] = NodeType.IamRole,
        ["aws_s3_bucket"] = NodeType.Resource,
        ["aws_ecs_task_definition"] = NodeType.Task,

        // A service is a different Terraform resource than the task definition it runs, but
        // the same kind of thing to an attacker moving through the graph: a deployed workload.
        // Modeling it as a distinct NodeType would need a SEC-03 change this ticket doesn't
        // make, so it folds into Task instead.
        ["aws_ecs_service"] = NodeType.Task,
    };

    /// <summary>
    /// True and sets <paramref name="nodeType"/> when this Terraform resource type has a
    /// canonical home. False for anything else — the caller drops that resource as noise,
    /// exactly like it drops provider nodes and module/operation scaffolding.
    /// </summary>
    public static bool TryMap(string terraformResourceType, out NodeType nodeType) =>
        Map.TryGetValue(terraformResourceType, out nodeType);
}

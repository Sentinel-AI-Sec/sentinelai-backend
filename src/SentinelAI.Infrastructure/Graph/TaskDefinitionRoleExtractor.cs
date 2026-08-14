using System.Text.RegularExpressions;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// Reads the IAM roles each <c>aws_ecs_task_definition</c> block attaches to itself
/// (<c>task_role_arn</c>, <c>execution_role_arn</c>), so the infra spine can emit the
/// <c>assumes</c> edge in the direction an attacker actually moves.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists at all, given the DOT graph already contains that dependency.</b>
/// <see cref="AttackDirectionOrienter"/> reverses every Terraform edge, because Terraform's
/// direction is build order and attack movement is generally the other way. For the
/// task-definition → role dependency that reversal produces <c>iam_role → task</c>, and the
/// flagship chain needs the opposite: an attacker executing inside the task assumes its role
/// and reaches the bucket from there. Rather than special-case the orienter — whose blanket
/// reversal is correct for the resource types it was written against, and whose regression
/// test is the project's standing guard against the zero-chains bug — the spine emits the
/// <c>assumes</c> edge explicitly from the reference that creates it, and drops the reversed
/// edge for that same pair.
/// </para>
/// <para>
/// <b>Both edges used to be kept</b>, on the argument that traversal's ATT&amp;CK tactic
/// ordering discards the backwards one. It does, but only inside the traverser: the stored
/// graph still held <c>role → task</c> and <c>task → role</c>, both <c>certain</c>, which is a
/// contradiction for every other consumer and a two-node cycle across the flagship chain's IAM
/// hop. <c>TerraformInfraSpineReader.BuildAssumesEdges</c> carries the full reasoning for which
/// direction survives.
/// </para>
/// <para>
/// Literal <c>aws_iam_role.&lt;name&gt;</c> references only, matching
/// <see cref="TerraformHclParser"/>'s own limits: a role ARN built from a variable or a data
/// source is invisible here, exactly as it is invisible to Terraform's own literal reference
/// edges.
/// </para>
/// </remarks>
internal static partial class TaskDefinitionRoleExtractor
{
    [GeneratedRegex("""resource\s+"aws_ecs_task_definition"\s+"([A-Za-z0-9_]+)"\s*\{""", RegexOptions.CultureInvariant)]
    private static partial Regex TaskDefinitionHeader();

    [GeneratedRegex(
        """(?:task_role_arn|execution_role_arn)\s*=\s*aws_iam_role\.([A-Za-z_][A-Za-z0-9_]*)""",
        RegexOptions.CultureInvariant)]
    private static partial Regex RoleArnReference();

    /// <summary>
    /// Task definition resource name (e.g. <c>order_task</c>) → the role resource names it
    /// references, de-duplicated and in source order. A task definition whose roles are all
    /// non-literal is absent rather than mapped to an empty set.
    /// </summary>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> ExtractRoleNamesByTaskDefinitionName(
        IReadOnlyDictionary<string, string> hclFiles)
    {
        var result = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        if (hclFiles.Count == 0) return result;

        var combined = string.Join('\n', hclFiles.Values);

        foreach (Match header in TaskDefinitionHeader().Matches(combined))
        {
            var bodyStart = header.Index + header.Length;
            var bodyEnd = FindMatchingBrace(combined, bodyStart);
            if (bodyEnd < 0) continue;

            var roles = new List<string>();
            foreach (Match reference in RoleArnReference().Matches(combined[bodyStart..bodyEnd]))
            {
                var role = reference.Groups[1].Value;
                if (!roles.Contains(role, StringComparer.Ordinal)) roles.Add(role);
            }

            // The execution role and the task role are commonly the same role (the fixture's
            // order_task sets both to order_task_role); one edge, not two.
            if (roles.Count > 0) result[header.Groups[1].Value] = roles;
        }

        return result;
    }

    /// <summary>Mirrors <c>TerraformHclParser.FindMatchingBrace</c> — see
    /// <see cref="TerraformIamPolicyParser"/>'s doc remarks for why this is a separate copy.</summary>
    private static int FindMatchingBrace(string text, int bodyStart)
    {
        var depth = 1;
        for (var i = bodyStart; i < text.Length; i++)
        {
            if (text[i] == '{') depth++;
            else if (text[i] == '}' && --depth == 0) return i;
        }

        return -1;
    }
}

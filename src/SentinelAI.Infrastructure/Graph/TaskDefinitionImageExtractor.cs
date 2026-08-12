using System.Text.RegularExpressions;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-19, infra side, step 2: reads the raw (possibly variable-referencing) container image
/// field out of each <c>aws_ecs_task_definition</c> block's <c>container_definitions</c>.
/// </summary>
/// <remarks>
/// <c>container_definitions</c> shows up in real Terraform two ways — <c>jsonencode([{ image =
/// "..." }])</c> (HCL object syntax, <c>=</c>) or a raw JSON heredoc (<c>&lt;&lt;JSON ... "image":
/// "..." ... JSON</c>). This reads for either literal shape rather than committing to one, since
/// nothing about the ticket says which this fixture uses. What it does not do is evaluate
/// <c>jsonencode()</c> or parse real JSON — both are treated as text to pattern-match over, same
/// spirit as <c>TerraformHclParser</c> not evaluating HCL expressions.
/// </remarks>
internal static partial class TaskDefinitionImageExtractor
{
    [GeneratedRegex("""resource\s+"aws_ecs_task_definition"\s+"([A-Za-z0-9_]+)"\s*\{""", RegexOptions.CultureInvariant)]
    private static partial Regex TaskDefinitionHeader();

    [GeneratedRegex(""""(?:"image"\s*:|image\s*=)\s*"([^"]*)"""", RegexOptions.CultureInvariant)]
    private static partial Regex ImageField();

    /// <summary>Task definition resource name (e.g. <c>order_task</c>) → its raw, unresolved
    /// image field text. A task definition with no readable <c>image</c> field is absent from
    /// the result rather than mapped to an empty string.</summary>
    public static IReadOnlyDictionary<string, string> ExtractImageRefsByTaskDefinitionName(
        IReadOnlyDictionary<string, string> hclFiles)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (hclFiles.Count == 0) return result;

        var combined = string.Join('\n', hclFiles.Values);

        foreach (Match header in TaskDefinitionHeader().Matches(combined))
        {
            var bodyStart = header.Index + header.Length;
            var bodyEnd = FindMatchingBrace(combined, bodyStart);
            if (bodyEnd < 0) continue;

            var image = ImageField().Match(combined[bodyStart..bodyEnd]);
            if (image.Success) result[header.Groups[1].Value] = image.Groups[1].Value;
        }

        return result;
    }

    /// <summary>Mirrors <c>TerraformHclParser.FindMatchingBrace</c> exactly — see
    /// <see cref="TerraformIamPolicyParser"/>'s doc remarks for why this is a separate copy
    /// rather than a shared call.</summary>
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

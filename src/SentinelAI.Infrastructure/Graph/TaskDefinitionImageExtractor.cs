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

    /// <summary>
    /// The <c>image</c> value, in either of the two shapes HCL writes it: a quoted string
    /// (<c>image = "repo/name:tag"</c>, which also covers <c>image = "${var.x}"</c>) or a bare
    /// expression referencing a variable or a local (<c>image = var.legacy_worker_image</c>).
    /// </summary>
    /// <remarks>
    /// <b>The bare alternative is not a nicety; without it a whole confidence tier is dead code.</b>
    /// This pattern used to require the quotes. The fixture's second task definition
    /// (<c>legacy_worker_task</c>) exists precisely to exercise SEC-19's <c>unresolved</c> tier and
    /// writes <c>image = var.legacy_worker_image</c> — unquoted, because that is how a Terraform
    /// author writes a plain variable reference. A quotes-only pattern therefore did not match it,
    /// the task was absent from this result entirely, <see cref="CodeInfraSeamReader"/> saw nothing
    /// to join, and SEC-19's second acceptance criterion ("no confident match but both reference an
    /// image → unresolved edge recorded") could not be satisfied by any input the fixture contains.
    /// The failure was silent in the worst way: the seam looked healthy because the only task it
    /// could see was the one that matches.
    /// <para>
    /// Only <c>var.</c>/<c>local.</c> references are accepted bare, not arbitrary HCL. That keeps
    /// the widening to exactly the shape <see cref="TerraformVariableResolver.Substitute"/> already
    /// resolves — its <c>BareReference</c> pass was written for this and had never been handed one
    /// from here — rather than admitting function calls or interpolated expressions this file has
    /// no way to evaluate and would silently compare as literal text.
    /// </para>
    /// </remarks>
    [GeneratedRegex(
        """(?:"image"\s*:|image\s*=)\s*(?:"(?<quoted>[^"]*)"|(?<bare>(?:var|local)\.[A-Za-z_][A-Za-z0-9_]*))""",
        RegexOptions.CultureInvariant)]
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
            if (!image.Success) continue;

            // Exactly one of the two alternatives matched; the other group is unsuccessful and
            // its Value would be "". Reading Groups["quoted"].Value unconditionally would map a
            // bare reference to an empty string, which ImageNameNormalizer then rejects — the
            // same "absent task definition" outcome the quotes-only pattern used to produce,
            // just one line later.
            var quoted = image.Groups["quoted"];
            result[header.Groups[1].Value] = quoted.Success ? quoted.Value : image.Groups["bare"].Value;
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

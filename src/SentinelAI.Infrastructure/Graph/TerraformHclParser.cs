using System.Text.RegularExpressions;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-17 step 4: a degraded fallback used only when the DOT graph is missing, empty, or
/// produced no usable nodes/edges (<c>terraform init</c> didn't run on the runner, say).
/// Reconstructs an equivalent-ish set of resource nodes and their direct references straight
/// from the raw <c>.tf</c> source, so the infra spine still has something rather than nothing.
/// Returns the same <see cref="TerraformRawGraph"/> shape <see cref="TerraformDotParser"/>
/// does, so everything downstream of step 1 (reorientation, type mapping, canonicalization)
/// treats both sources identically.
/// </summary>
/// <remarks>
/// This is explicitly NOT a complete HCL graph builder — it is a fallback for when the good
/// path (DOT, which is Terraform's own fully-resolved dependency graph) isn't available. What
/// it supports:
/// <list type="bullet">
/// <item>Top-level <c>resource "type" "name" { ... }</c> blocks in the root module only — no
/// <c>module</c> block traversal, so a fallback-parsed graph never has module-qualified
/// addresses (unlike the DOT path, which can).</item>
/// <item>A reference is any literal <c>type.name</c> occurrence, of another declared resource,
/// found anywhere in that resource's own block body — covering the common case
/// (<c>role = aws_iam_role.order_task_role.id</c>) without evaluating HCL expressions.</item>
/// </list>
/// What it explicitly does NOT support, on purpose:
/// <list type="bullet">
/// <item>Computed or dynamic references (interpolations built from variables/locals/conditionals
/// that only resolve at <c>terraform plan</c> time) — those aren't literal <c>type.name</c> text
/// and so are invisible to this parser, same as they were invisible to the wildcard-policy
/// example this fixture is built around.</item>
/// <item><c>for_each</c>/<c>count</c> expansion — a resource declared with either produces one
/// node here (the declaration), not one per expanded instance.</item>
/// <item>String literals that happen to contain brace characters — block-body extraction is
/// plain brace counting, not an HCL tokenizer, so a body containing an unbalanced <c>{</c>/<c>}</c>
/// inside a quoted string would mis-scope. Not a concern for the resource blocks this ticket's
/// fixture uses (JSON policy documents go through <c>jsonencode({...})</c>, which balances).</item>
/// </list>
/// </remarks>
internal static partial class TerraformHclParser
{
    [GeneratedRegex("""resource\s+"([A-Za-z0-9_]+)"\s+"([A-Za-z0-9_]+)"\s*\{""", RegexOptions.CultureInvariant)]
    private static partial Regex ResourceBlockHeader();

    [GeneratedRegex(@"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.CultureInvariant)]
    private static partial Regex DottedReference();

    public static TerraformRawGraph Parse(IReadOnlyDictionary<string, string> hclFiles)
    {
        if (hclFiles.Count == 0) return new TerraformRawGraph([], []);

        // Terraform doesn't care about file boundaries within one directory — a resource in
        // main.tf can reference one in iam.tf — so every file is parsed as one combined source.
        var combined = string.Join('\n', hclFiles.Values);

        var blocks = new List<(string Address, string ResourceType, string ResourceName, string Body)>();
        foreach (Match header in ResourceBlockHeader().Matches(combined))
        {
            var resourceType = header.Groups[1].Value;
            var resourceName = header.Groups[2].Value;

            var bodyStart = header.Index + header.Length;
            var bodyEnd = FindMatchingBrace(combined, bodyStart);
            if (bodyEnd < 0) continue; // unbalanced braces in the source — skip this block, don't throw

            blocks.Add(($"{resourceType}.{resourceName}", resourceType, resourceName, combined[bodyStart..bodyEnd]));
        }

        var declared = blocks.Select(b => b.Address).ToHashSet(StringComparer.Ordinal);
        var nodes = blocks
            .Select(b => new TerraformRawNode(b.Address, ModulePath: string.Empty, b.ResourceType, b.ResourceName))
            .ToList();

        var edgeAddresses = new HashSet<(string From, string To)>();
        foreach (var block in blocks)
        {
            foreach (Match reference in DottedReference().Matches(block.Body))
            {
                var candidate = $"{reference.Groups[1].Value}.{reference.Groups[2].Value}";
                if (candidate == block.Address) continue; // e.g. a self_link back onto its own type.name — not an edge
                if (declared.Contains(candidate))
                    edgeAddresses.Add((block.Address, candidate));
            }
        }

        var edges = edgeAddresses.Select(e => new TerraformRawEdge(e.From, e.To)).ToList();
        return new TerraformRawGraph(nodes, edges);
    }

    /// <summary>
    /// Index of the <c>}</c> that closes the brace already consumed just before
    /// <paramref name="bodyStart"/>, or -1 if the braces never balance.
    /// </summary>
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

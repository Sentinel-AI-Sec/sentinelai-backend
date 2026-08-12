using System.Text.RegularExpressions;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-19, infra side, step 1: resolves Terraform <c>variable</c> defaults and <c>locals</c> so
/// a task definition's <c>image</c> field can be compared even when it references one
/// (<c>${var.order_image}</c>) instead of naming a literal string.
/// </summary>
/// <remarks>
/// Only <c>default</c> values are read for <c>variable</c> blocks — this reader has no
/// <c>terraform.tfvars</c> or CLI <c>-var</c> input to consult, so a variable with no default is
/// left unresolved. That is a real, expected gap: it means a variable the runner would override
/// at apply-time might not resolve here, which surfaces as an <c>Unresolved</c>-confidence edge
/// rather than a wrong match — the safe failure direction for a heuristic seam.
/// </remarks>
internal static partial class TerraformVariableResolver
{
    [GeneratedRegex("""variable\s+"([A-Za-z0-9_]+)"\s*\{""", RegexOptions.CultureInvariant)]
    private static partial Regex VariableBlockHeader();

    [GeneratedRegex(""""default\s*=\s*"([^"]*)"""", RegexOptions.CultureInvariant)]
    private static partial Regex DefaultField();

    [GeneratedRegex(@"locals\s*\{", RegexOptions.CultureInvariant)]
    private static partial Regex LocalsBlockHeader();

    [GeneratedRegex(""""([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"""", RegexOptions.CultureInvariant)]
    private static partial Regex LocalAssignment();

    [GeneratedRegex(@"\$\{\s*(var|local)\.([A-Za-z_][A-Za-z0-9_]*)\s*\}", RegexOptions.CultureInvariant)]
    private static partial Regex InterpolatedReference();

    [GeneratedRegex(@"(?<![\w.$])(var|local)\.([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.CultureInvariant)]
    private static partial Regex BareReference();

    public static TerraformVariables Resolve(IReadOnlyDictionary<string, string> hclFiles)
    {
        if (hclFiles.Count == 0) return new TerraformVariables(new Dictionary<string, string>(), new Dictionary<string, string>());

        var combined = string.Join('\n', hclFiles.Values);

        var variables = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match header in VariableBlockHeader().Matches(combined))
        {
            var bodyStart = header.Index + header.Length;
            var bodyEnd = FindMatchingBrace(combined, bodyStart);
            if (bodyEnd < 0) continue;

            var defaultValue = DefaultField().Match(combined[bodyStart..bodyEnd]);
            if (defaultValue.Success) variables[header.Groups[1].Value] = defaultValue.Groups[1].Value;
        }

        var locals = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match header in LocalsBlockHeader().Matches(combined))
        {
            var bodyStart = header.Index + header.Length;
            var bodyEnd = FindMatchingBrace(combined, bodyStart);
            if (bodyEnd < 0) continue;

            foreach (Match assignment in LocalAssignment().Matches(combined[bodyStart..bodyEnd]))
                locals[assignment.Groups[1].Value] = assignment.Groups[2].Value;
        }

        return new TerraformVariables(variables, locals);
    }

    /// <summary>
    /// Resolves every <c>${var.x}</c>/<c>var.x</c>/<c>${local.x}</c>/<c>local.x</c> reference in
    /// <paramref name="raw"/> that <paramref name="variables"/> has an answer for. A reference
    /// with no known value is left as its literal source text — visibly unresolved rather than
    /// silently blanked out, so a comparison against it reads as a mismatch instead of an
    /// accidental empty-string match.
    /// </summary>
    /// <returns>The substituted text, and whether at least one reference was actually resolved
    /// — the flag <see cref="SentinelAI.Domain.Abstractions.CodeInfraSeamEdge.ResolvedVariable"/> surfaces.</returns>
    public static (string Text, bool ResolvedVariable) Substitute(string raw, TerraformVariables variables)
    {
        var resolvedAny = false;

        string Resolve(string kind, string name)
        {
            var map = string.Equals(kind, "var", StringComparison.OrdinalIgnoreCase) ? variables.Variables : variables.Locals;
            if (!map.TryGetValue(name, out var value)) return $"{kind}.{name}";

            resolvedAny = true;
            return value;
        }

        var afterInterpolated = InterpolatedReference().Replace(raw, m => Resolve(m.Groups[1].Value, m.Groups[2].Value));
        var afterBare = BareReference().Replace(afterInterpolated, m => Resolve(m.Groups[1].Value, m.Groups[2].Value));

        return (afterBare, resolvedAny);
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

/// <param name="Variables">Terraform <c>variable</c> name → its <c>default</c> value.</param>
/// <param name="Locals">Terraform <c>locals</c> name → its literal value.</param>
internal sealed record TerraformVariables(IReadOnlyDictionary<string, string> Variables, IReadOnlyDictionary<string, string> Locals);

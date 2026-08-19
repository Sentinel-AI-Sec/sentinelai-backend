using System.Text.RegularExpressions;

namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// Pulls the linking keys — a CWE weakness id or a CVE vulnerability id — out of the free-form
/// strings scanners scatter them across (rule ids, tags, property bags).
/// </summary>
/// <remarks>
/// A finding is joined to knowledge and to the graph by its CWE/CVE, so recovering it from
/// wherever a given tool happened to put it is the whole point of normalization. Matching is
/// deliberately strict on shape (<c>CWE-502</c>, <c>CVE-2021-44228</c>) so a bare number in an
/// unrelated field is never mistaken for one.
/// </remarks>
internal static partial class LinkingKeys
{
    [GeneratedRegex(@"CWE-\d+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CwePattern();

    [GeneratedRegex(@"CVE-\d{4}-\d{4,}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CvePattern();

    /// <summary>The first CWE id found across the candidates, upper-cased, or null.</summary>
    public static string? FindCwe(IEnumerable<string?> candidates) => First(CwePattern(), candidates);

    /// <summary>The first CVE id found across the candidates, upper-cased, or null.</summary>
    public static string? FindCve(IEnumerable<string?> candidates) => First(CvePattern(), candidates);

    /// <summary>True when the text carries a CVE id.</summary>
    public static bool HasCve(params string?[] candidates) => FindCve(candidates) is not null;

    private static string? First(Regex pattern, IEnumerable<string?> candidates)
    {
        foreach (var candidate in candidates)
        {
            if (string.IsNullOrEmpty(candidate)) continue;
            var match = pattern.Match(candidate);
            if (match.Success) return match.Value.ToUpperInvariant();
        }

        return null;
    }
}

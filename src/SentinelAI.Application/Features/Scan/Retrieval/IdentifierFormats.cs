using System.Text.RegularExpressions;

namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// Decides whether a finding's CVE/CWE is <em>clean</em> — well-formed in the exact shape the
/// knowledge corpus indexed — and rewrites the near-misses into that shape.
/// </summary>
/// <remarks>
/// <para>
/// The retrieval decision tree (SEC-22) forks on one question: "does this finding have a clean
/// CVE or CWE id?" Answering it needs the corpus's own identifier grammar, which
/// <c>PIPELINE_A_CONTEXT.md</c> §3 pins as measured across all 32,432 chunks:
/// <c>CVE-&lt;4 digits&gt;-&lt;digits&gt;</c> and <c>CWE-&lt;digits&gt;</c>. Deciding it here rather
/// than in SEC-22 means the exact-filter path is handed an id that is already known to match a
/// payload key, instead of one that merely looks like an id.
/// </para>
/// <para>
/// Near-misses are normalized rather than rejected because scanners are inconsistent about the
/// separator — <c>cwe-502</c>, <c>CWE 502</c> and <c>CWE:502</c> all appear in real SARIF tag
/// arrays. A rejected id costs a finding its whole exact-filter path and silently demotes it to
/// a semantic query, which is the "confident and irrelevant" failure §4 warns about.
/// </para>
/// </remarks>
public static partial class IdentifierFormats
{
    /// <summary>The corpus form: <c>CVE-2024-21907</c>.</summary>
    [GeneratedRegex(@"^CVE-\d{4}-\d{4,}$", RegexOptions.CultureInvariant)]
    private static partial Regex CanonicalCve();

    /// <summary>The corpus form: <c>CWE-502</c>.</summary>
    [GeneratedRegex(@"^CWE-\d+$", RegexOptions.CultureInvariant)]
    private static partial Regex CanonicalCwe();

    /// <summary>Tolerated input: any of <c>-</c>, <c>_</c>, <c>:</c>, whitespace, or nothing.</summary>
    [GeneratedRegex(@"^\s*CVE[\s_:\-]*(\d{4})[\s_:\-]+(\d{4,})\s*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LooseCve();

    [GeneratedRegex(@"^\s*CWE[\s_:\-]*(\d+)\s*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LooseCwe();

    /// <summary>True when the value is already exactly what the corpus payload holds.</summary>
    public static bool IsCanonicalCve(string? value) => value is not null && CanonicalCve().IsMatch(value);

    /// <summary>True when the value is already exactly what the corpus payload holds.</summary>
    public static bool IsCanonicalCwe(string? value) => value is not null && CanonicalCwe().IsMatch(value);

    /// <summary>
    /// The corpus-shaped CVE id, or null when the value is absent or is not a CVE at all.
    /// </summary>
    public static string? NormalizeCve(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        var trimmed = value.Trim();
        if (CanonicalCve().IsMatch(trimmed)) return trimmed;

        var match = LooseCve().Match(trimmed);
        return match.Success ? $"CVE-{match.Groups[1].Value}-{match.Groups[2].Value}" : null;
    }

    /// <summary>
    /// The corpus-shaped CWE id, or null when the value is absent or is not a CWE at all.
    /// </summary>
    /// <remarks>
    /// Leading zeros are dropped (<c>CWE-0502</c> → <c>CWE-502</c>): the corpus stores the
    /// integer form, and a zero-padded filter value matches nothing while erroring on nothing.
    /// </remarks>
    public static string? NormalizeCwe(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        var trimmed = value.Trim();
        if (CanonicalCwe().IsMatch(trimmed)) return Rebuild(trimmed[4..]);

        var match = LooseCwe().Match(trimmed);
        return match.Success ? Rebuild(match.Groups[1].Value) : null;

        static string? Rebuild(string digits) =>
            ulong.TryParse(digits, out var number) ? $"CWE-{number}" : null;
    }
}

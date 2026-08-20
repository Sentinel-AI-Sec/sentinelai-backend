using System.Text.Json;
using System.Text.RegularExpressions;
using SentinelAI.Application.Features.Benchmark;

namespace SentinelAI.Benchmark;

/// <summary>
/// Turns a tool's SARIF export into <see cref="ToolFinding"/>s the scorer can compare.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is not <c>SarifReader</c> from Infrastructure.</b> That one produces SentinelAI
/// <c>Finding</c>s — tenant, scan job, node reference, severity scale, rule-mapping resolution —
/// which a competitor's export has none of and does not need. What SEC-39 needs from a SARIF
/// file is four fields: project, path, line, and a weakness class. Reusing the domain extractor
/// would mean inventing a tenant id for Snyk's output, and the resulting coupling would make a
/// change to our normalization silently change our competitors' scores.
/// </para>
/// <para>
/// <b>The weakness class is read from the rule's tags</b>, which is where every one of these
/// tools puts it: SonarQube writes <c>CWE-89</c> into <c>properties.tags</c>, Snyk writes it
/// into <c>properties.cwe</c> or the tags, Checkov into the tags. A result whose rule carries no
/// CWE is emitted with an empty category and will match no label — visible in the report as an
/// unlabelled finding, which is the honest place for it.
/// </para>
/// </remarks>
internal static partial class SarifToolFindings
{
    /// <summary>Matches a CWE identifier anywhere in a tag, property or rule id.</summary>
    [GeneratedRegex(@"CWE[-_ ]?(\d{1,5})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CweId();

    /// <summary>
    /// Reads every result in every run.
    /// </summary>
    /// <param name="sarif">The document text.</param>
    /// <param name="tool">
    /// The tool name to stamp on each finding. Taken from the file name rather than from the
    /// SARIF driver, because the driver names vary between versions of the same product
    /// ("SonarQube", "sonarqube-scanner", "SonarLint") and the report's columns should not.
    /// </param>
    /// <param name="projects">
    /// The corpus's project names, when they are known. Supplying them is what lets an absolute
    /// build-agent path be split correctly — see <see cref="Split"/>.
    /// </param>
    public static IReadOnlyList<ToolFinding> Read(
        string sarif, string tool, IReadOnlySet<string>? projects = null)
    {
        using var document = JsonDocument.Parse(sarif);

        if (!document.RootElement.TryGetProperty("runs", out var runs)) return [];

        var findings = new List<ToolFinding>();

        foreach (var run in runs.EnumerateArray())
        {
            var categoriesByRule = RuleCategories(run);

            if (!run.TryGetProperty("results", out var results)) continue;

            foreach (var result in results.EnumerateArray())
            {
                var ruleId = result.TryGetProperty("ruleId", out var id) ? id.GetString() : null;

                var category = ruleId is not null && categoriesByRule.TryGetValue(ruleId, out var mapped)
                    ? mapped
                    // Some tools put the CWE in the rule id itself (Trivy reports CVE ids, Snyk
                    // reports SNYK-CWE-89). Falling back to the id costs nothing and recovers a
                    // category that would otherwise be dropped.
                    : CategoryIn(ruleId);

                var (file, line) = Location(result);

                if (file is null) continue;

                var (project, relative) = Split(file, projects);

                findings.Add(new ToolFinding(
                    Tool: tool,
                    Project: project,
                    File: relative,
                    Line: line,
                    Category: category,
                    RuleId: ruleId));
            }
        }

        return findings;
    }

    /// <summary>Each rule's weakness class, from wherever this tool wrote it.</summary>
    private static Dictionary<string, string> RuleCategories(JsonElement run)
    {
        var categories = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // SARIF v2 puts rules under tool.driver.rules; v1 puts them under run.rules. Checkov
        // still emits v1, so reading only one shape drops a whole tool's categories.
        var rules = run.TryGetProperty("tool", out var toolElement)
            && toolElement.TryGetProperty("driver", out var driver)
            && driver.TryGetProperty("rules", out var v2)
                ? v2
                : run.TryGetProperty("rules", out var v1) ? v1 : default;

        if (rules.ValueKind != JsonValueKind.Array) return categories;

        foreach (var rule in rules.EnumerateArray())
        {
            if (!rule.TryGetProperty("id", out var id) || id.GetString() is not { Length: > 0 } ruleId)
                continue;

            categories[ruleId] = CategoryIn(rule);
        }

        return categories;
    }

    /// <summary>The first CWE mentioned anywhere in a rule's tags, properties or id.</summary>
    private static string CategoryIn(JsonElement rule)
    {
        if (rule.TryGetProperty("properties", out var properties))
        {
            if (properties.TryGetProperty("tags", out var tags) && tags.ValueKind == JsonValueKind.Array)
            {
                foreach (var tag in tags.EnumerateArray())
                {
                    if (CategoryIn(tag.GetString()) is { Length: > 0 } fromTag) return fromTag;
                }
            }

            // Snyk writes properties.cwe as an array of ids.
            if (properties.TryGetProperty("cwe", out var cwe))
            {
                var text = cwe.ValueKind == JsonValueKind.Array
                    ? string.Join(" ", cwe.EnumerateArray().Select(c => c.ToString()))
                    : cwe.ToString();

                if (CategoryIn(text) is { Length: > 0 } fromProperty) return fromProperty;
            }
        }

        return rule.TryGetProperty("id", out var id) ? CategoryIn(id.GetString()) : string.Empty;
    }

    /// <summary>Normalises whatever spelling a tool used into <c>CWE-nnn</c>.</summary>
    private static string CategoryIn(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return string.Empty;

        var match = CweId().Match(text);

        if (!match.Success) return string.Empty;

        // Canonical form, so CWE-89, cwe_89, "CWE 89" and SonarQube's zero-padded
        // external/cwe/cwe-089 are one category rather than four columns that each score a
        // quarter of the detections. Parsed to an int and back precisely to drop the padding.
        return int.TryParse(match.Groups[1].Value, out var number)
            ? $"CWE-{number}"
            : string.Empty;
    }

    private static (string? File, int Line) Location(JsonElement result)
    {
        if (!result.TryGetProperty("locations", out var locations)
            || locations.ValueKind != JsonValueKind.Array)
            return (null, 0);

        foreach (var location in locations.EnumerateArray())
        {
            if (!location.TryGetProperty("physicalLocation", out var physical)) continue;

            var uri = physical.TryGetProperty("artifactLocation", out var artifact)
                && artifact.TryGetProperty("uri", out var value)
                    ? value.GetString()
                    : null;

            if (uri is null) continue;

            var line = physical.TryGetProperty("region", out var region)
                && region.TryGetProperty("startLine", out var start)
                    ? start.GetInt32()
                    : 0;

            return (uri, line);
        }

        return (null, 0);
    }

    /// <summary>
    /// Splits a reported path into the corpus project it belongs to and the path within it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The corpus is laid out one directory per project (<c>terragoat/</c>,
    /// <c>kubernetes-goat/</c>, <c>cfngoat/</c>, …), and a label records the path <em>within</em>
    /// its project. Tools do not cooperate: Snyk reports <c>terragoat/infra/iam.tf</c> while
    /// SonarQube reports <c>/home/runner/work/corpus/terragoat/src/App/Shell.cs</c>, and the
    /// leading segment of the second is <c>home</c>.
    /// </para>
    /// <para>
    /// <b>So the split is made against the project names the corpus actually has</b>, taken from
    /// its labels: the first segment that names a known project is the project, and everything
    /// after it is the file. That is exact where the information exists, and it degrades to the
    /// first segment where it does not — which surfaces in the report as a project with no
    /// labels rather than as findings silently scored against the wrong one.
    /// </para>
    /// </remarks>
    private static (string Project, string File) Split(string uri, IReadOnlySet<string>? projects)
    {
        var segments = Normalize(uri).Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (segments.Length == 0) return (string.Empty, string.Empty);
        if (segments.Length == 1) return (segments[0], segments[0]);

        // Last match rather than first: a corpus checked out at
        // /home/runner/work/terragoat/terragoat repeats the name, and the project directory is
        // the innermost one.
        var index = -1;

        if (projects is not null)
        {
            for (var i = 0; i < segments.Length - 1; i++)
                if (projects.Contains(segments[i])) index = i;
        }

        if (index < 0) index = 0;

        return (segments[index], string.Join('/', segments[(index + 1)..]));
    }

    /// <summary>
    /// Strips the <c>file://</c> scheme and the absolute build-agent prefix tools emit.
    /// </summary>
    /// <remarks>
    /// Roslyn and SonarQube both report the absolute path on the machine that ran them
    /// (<c>file:///home/runner/work/repo/repo/src/…</c>). Comparing those against a
    /// repository-relative label matches nothing, and every finding becomes unlabelled — the
    /// failure that reads as perfect precision over an empty denominator.
    /// </remarks>
    private static string Normalize(string uri)
    {
        var path = uri.Replace('\\', '/');

        if (path.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
            path = path["file://".Length..].TrimStart('/');

        // Windows drive letters survive the scheme strip as "C:/Users/…".
        if (path.Length > 2 && path[1] == ':') path = path[3..];

        return path.TrimStart('.', '/');
    }
}

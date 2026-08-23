using System.Text.Json.Serialization;

namespace SentinelAI.Application.Features.Benchmark;

/// <summary>
/// One labelled location in the SEC-38 benchmark corpus: a place a human decided either does or
/// does not hold a real vulnerability.
/// </summary>
/// <remarks>
/// <para>
/// <b>Both polarities are labels.</b> A corpus of only-vulnerable places can measure recall and
/// cannot measure precision, because nothing tells a scorer that a report at line 40 is wrong —
/// it might be a weakness the labellers simply had not got to. <see cref="IsVulnerable"/> false
/// is a positive statement that this place is clean, and it is what makes a false positive
/// distinguishable from an unlabelled one.
/// </para>
/// <para>
/// <b><see cref="Category"/> is the unit precision and recall are reported per.</b> A tool that
/// finds every IAM misconfiguration and no injection has an unremarkable overall recall and a
/// very informative per-category one, and the whole point of SEC-39 is that the second number
/// exists.
/// </para>
/// </remarks>
/// <param name="Id">Stable label id, e.g. <c>terragoat-iam-01</c>. Used in the report so a
/// disputed classification can be looked up.</param>
/// <param name="Project">Which corpus project this label belongs to, e.g. <c>terragoat</c>.</param>
/// <param name="File">Repository-relative path, forward slashes.</param>
/// <param name="Line">1-based line. Zero means the label is about the file as a whole.</param>
/// <param name="Category">The weakness class — a CWE id where one applies.</param>
/// <param name="IsVulnerable">
/// True when a real vulnerability is here; false when this is a deliberately clean sample.
/// </param>
/// <param name="Note">Why the labeller decided this. Carried into the report for disputes.</param>
public sealed record GroundTruthLabel(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("project")] string Project,
    [property: JsonPropertyName("file")] string File,
    [property: JsonPropertyName("line")] int Line,
    [property: JsonPropertyName("category")] string Category,
    [property: JsonPropertyName("is_vulnerable")] bool IsVulnerable,
    [property: JsonPropertyName("note")] string? Note = null);

/// <summary>
/// One finding a tool reported, normalised to the shape the scorer compares.
/// </summary>
/// <remarks>
/// Deliberately not <c>Finding</c>. That type is SentinelAI's own domain model and carries a
/// tenant, a scan job and a node reference — none of which SonarQube or Snyk has. Scoring three
/// tools against one corpus needs a shape all three can be expressed in, and inventing tenant
/// ids for a competitor's SARIF to reuse a type would be the wrong kind of economy.
/// </remarks>
/// <param name="Tool">Which tool reported it — the column it lands in.</param>
/// <param name="Project">Which corpus project it was reported against.</param>
/// <param name="File">Repository-relative path, forward slashes.</param>
/// <param name="Line">1-based line, or zero for a file-level report.</param>
/// <param name="Category">The weakness class the tool assigned, normalised to a CWE id.</param>
/// <param name="RuleId">The tool's own rule id, kept so an unmatched report can be investigated.</param>
public sealed record ToolFinding(
    [property: JsonPropertyName("tool")] string Tool,
    [property: JsonPropertyName("project")] string Project,
    [property: JsonPropertyName("file")] string File,
    [property: JsonPropertyName("line")] int Line,
    [property: JsonPropertyName("category")] string Category,
    [property: JsonPropertyName("rule_id")] string? RuleId = null);

/// <summary>
/// The tool names the benchmark reports side by side (SEC-39).
/// </summary>
/// <remarks>
/// Constants rather than an enum: these are the keys in the corpus's own files, written by
/// whoever exported each tool's output, and an unknown tool should appear in the report as its
/// own column rather than fail to parse.
/// </remarks>
public static class BenchmarkTools
{
    public const string SentinelAi = "sentinelai";
    public const string SonarQube = "sonarqube";
    public const string Snyk = "snyk";

    /// <summary>The three the acceptance criterion names, in report order.</summary>
    public static readonly IReadOnlyList<string> Compared = [SentinelAi, SonarQube, Snyk];
}

namespace SentinelAI.Application.Features.Benchmark;

/// <summary>
/// How close a reported line has to be to a labelled one to count as the same issue.
/// </summary>
/// <remarks>
/// <para>
/// <b>Not zero, and the reason is the tools rather than a wish to flatter them.</b> Checkov
/// reports a Terraform misconfiguration at the line of the offending attribute; Snyk reports the
/// same issue at the line of the enclosing <c>resource</c> block; SonarQube reports a C# issue
/// at the statement while a labeller records the method. Requiring exact equality would score
/// two tools as having missed an issue they both found, and the resulting recall figure would be
/// a measure of line-numbering convention, not of detection.
/// </para>
/// <para>
/// <b>Not large either.</b> A window wide enough to swallow a whole file turns precision into
/// "did the tool say anything about this file", which is the number every scanner wins. Three
/// lines either way is the span of the block a finding is normally reported within, and it is
/// stated here as a constant so it appears in the report rather than living in someone's head.
/// </para>
/// <para>
/// <b>A file-level label or report (line 0) matches anything in that file</b>, in the same
/// category. That is what "line 0" means, and treating it as line zero would make it match
/// nothing.
/// </para>
/// </remarks>
public sealed record MatchWindow(int Lines)
{
    /// <summary>The window the published figures use.</summary>
    public static readonly MatchWindow Default = new(3);

    /// <summary>Exact-line matching, for a corpus whose labels are known to be line-precise.</summary>
    public static readonly MatchWindow Exact = new(0);

    public bool Covers(int labelLine, int reportedLine) =>
        labelLine == 0 || reportedLine == 0 || Math.Abs(labelLine - reportedLine) <= Lines;

    public override string ToString() => Lines == 0 ? "exact line" : $"±{Lines} lines";
}

/// <summary>
/// Precision and recall for one tool in one category, with the counts they were computed from.
/// </summary>
/// <remarks>
/// The counts travel with the ratios deliberately. "Precision 1.00" over one finding and over
/// four hundred are different claims, and a table of bare percentages hides which one it is —
/// which is exactly how a benchmark ends up flattering the tool with the fewest results.
/// </remarks>
/// <param name="Tool">Which tool.</param>
/// <param name="Category">The weakness class, or <see cref="CategoryScore.AllCategories"/>.</param>
/// <param name="TruePositives">Reports that matched a label marked vulnerable.</param>
/// <param name="FalsePositives">Reports that matched a label marked clean.</param>
/// <param name="FalseNegatives">Labels marked vulnerable that no report matched.</param>
/// <param name="Unlabelled">
/// Reports matching no label at all. <b>Not counted as anything</b> — see the remarks on
/// <see cref="Precision"/>.
/// </param>
public sealed record CategoryScore(
    string Tool,
    string Category,
    int TruePositives,
    int FalsePositives,
    int FalseNegatives,
    int Unlabelled)
{
    /// <summary>The pseudo-category the overall row is reported under.</summary>
    public const string AllCategories = "(all)";

    /// <summary>
    /// Of the reports this tool made that the corpus can judge, how many were real.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><see cref="Unlabelled"/> is excluded from both the numerator and the denominator, and
    /// that is the single most consequential decision in this file.</b> A report at a place the
    /// corpus says nothing about is not evidence the tool was wrong; the labellers may simply
    /// not have reached that line. Counting those as false positives would punish the tool that
    /// looks hardest, and would make precision a measure of how completely the corpus was
    /// labelled.
    /// </para>
    /// <para>
    /// It is not free, though, and pretending otherwise would be the dishonest version of this
    /// choice: a tool that reports a thousand unlabelled findings and two labelled correct ones
    /// scores 100% precision here. That is why the count is carried on this record and printed
    /// in the report next to the ratio. <b>Read them together or not at all.</b>
    /// </para>
    /// <para>
    /// A tool that made no judgeable report scores 1 rather than 0 — it has said nothing false.
    /// Recall is where saying nothing is punished, which is the division of labour SEC-39 asks
    /// for: precision as the false-positive headline, recall as the guardrail against a tool
    /// that buys it by staying quiet.
    /// </para>
    /// </remarks>
    public double Precision =>
        TruePositives + FalsePositives == 0 ? 1d : (double)TruePositives / (TruePositives + FalsePositives);

    /// <summary>Of the real vulnerabilities the corpus knows about, how many this tool found.</summary>
    /// <remarks>
    /// A category with no vulnerable labels scores 1: every one of its zero vulnerabilities was
    /// found. Returning 0 would make a category the corpus deliberately keeps clean look like a
    /// total detection failure.
    /// </remarks>
    public double Recall =>
        TruePositives + FalseNegatives == 0 ? 1d : (double)TruePositives / (TruePositives + FalseNegatives);

    /// <summary>The harmonic mean, for ranking. Zero when both halves are zero.</summary>
    public double F1 =>
        Precision + Recall == 0 ? 0d : 2 * Precision * Recall / (Precision + Recall);

    /// <summary>How many judgeable reports and known vulnerabilities this row rests on.</summary>
    /// <remarks>
    /// The honesty bound on the row. A score computed from three labels is a number, not
    /// evidence, and this is what lets a reader tell the difference at a glance.
    /// </remarks>
    public int Support => TruePositives + FalsePositives + FalseNegatives;
}

/// <summary>
/// The whole benchmark: every tool scored per category over one corpus (SEC-39).
/// </summary>
/// <param name="Corpus">What was measured — the corpus name and version, for the report header.</param>
/// <param name="Window">The line window used, so the figures can be reproduced.</param>
/// <param name="Scores">One row per tool per category, plus one <c>(all)</c> row per tool.</param>
/// <param name="Caveats">
/// Statements the numbers cannot make on their own — the C# ground-truth gap above all. See
/// <see cref="BenchmarkScorer"/>.
/// </param>
public sealed record BenchmarkReport(
    string Corpus,
    MatchWindow Window,
    IReadOnlyList<CategoryScore> Scores,
    IReadOnlyList<string> Caveats)
{
    /// <summary>The overall row for one tool.</summary>
    public CategoryScore? Overall(string tool) => Scores.FirstOrDefault(
        s => s.Tool == tool && s.Category == CategoryScore.AllCategories);

    /// <summary>Every category measured, in report order.</summary>
    public IReadOnlyList<string> Categories =>
    [
        .. Scores.Select(s => s.Category)
            .Where(c => c != CategoryScore.AllCategories)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(c => c, StringComparer.OrdinalIgnoreCase),
    ];

    /// <summary>Every tool that appeared, in report order.</summary>
    public IReadOnlyList<string> Tools =>
    [
        // The three the ticket names come first, in its order; anything else follows
        // alphabetically. A report whose columns move between runs is one nobody can diff.
        .. Scores.Select(s => s.Tool).Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(RankOf)
            .ThenBy(t => t, StringComparer.OrdinalIgnoreCase),
    ];

    /// <summary>Where a tool sits in <see cref="BenchmarkTools.Compared"/>, or last.</summary>
    private static int RankOf(string tool)
    {
        for (var i = 0; i < BenchmarkTools.Compared.Count; i++)
        {
            if (string.Equals(BenchmarkTools.Compared[i], tool, StringComparison.OrdinalIgnoreCase))
                return i;
        }

        return int.MaxValue;
    }

    /// <summary>This tool's row for this category, or null when it reported in neither.</summary>
    public CategoryScore? For(string tool, string category) => Scores.FirstOrDefault(
        s => string.Equals(s.Tool, tool, StringComparison.OrdinalIgnoreCase)
            && string.Equals(s.Category, category, StringComparison.OrdinalIgnoreCase));
}

using System.Globalization;
using System.Text;

namespace SentinelAI.Application.Features.Benchmark;

/// <summary>
/// Renders a <see cref="BenchmarkReport"/> as Markdown — the artefact SEC-39 hands to a reader.
/// </summary>
/// <remarks>
/// <para>
/// <b>Precision and recall are printed together, always, in the same cell.</b> The ticket is
/// explicit that precision is the false-positive headline and recall is the guardrail, and the
/// reason for the pairing is that either one alone can be bought with the other: a tool reports
/// one certain finding and takes 100% precision, or reports everything and takes 100% recall.
/// A layout that let a reader see one without the other would make the wrong number quotable.
/// </para>
/// <para>
/// <b>Support and unlabelled counts sit beside the ratios rather than in a footnote.</b> They
/// are what separates a measurement from a number, and a footnote is where a caveat goes to be
/// skipped.
/// </para>
/// </remarks>
public static class BenchmarkReportRenderer
{
    public static string ToMarkdown(BenchmarkReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var text = new StringBuilder();

        text.AppendLine("# Precision and recall vs SonarQube & Snyk (SEC-39)");
        text.AppendLine();
        text.AppendLine($"**Corpus:** {report.Corpus}  ");
        text.AppendLine($"**Matching:** project + file + category, line within {report.Window}  ");
        text.AppendLine($"**Tools:** {string.Join(", ", report.Tools)}");
        text.AppendLine();

        AppendOverall(text, report);
        AppendPerCategory(text, report);
        AppendCaveats(text, report);

        return text.ToString();
    }

    private static void AppendOverall(StringBuilder text, BenchmarkReport report)
    {
        text.AppendLine("## Overall");
        text.AppendLine();
        text.AppendLine("| Tool | Precision | Recall | F1 | TP | FP | FN | Unlabelled |");
        text.AppendLine("|---|---|---|---|---|---|---|---|");

        foreach (var tool in report.Tools)
        {
            var score = report.Overall(tool);

            if (score is null)
            {
                // A tool named for comparison that produced nothing at all. Printed as a row
                // rather than omitted: a missing column reads as "not measured", and "we ran it
                // and it found nothing" is a result.
                text.AppendLine($"| {tool} | — | — | — | 0 | 0 | 0 | 0 |");
                continue;
            }

            text.AppendLine(
                $"| {tool} | {Percent(score.Precision)} | {Percent(score.Recall)} | "
                + $"{score.F1.ToString("0.00", CultureInfo.InvariantCulture)} | "
                + $"{score.TruePositives} | {score.FalsePositives} | {score.FalseNegatives} | "
                + $"{score.Unlabelled} |");
        }

        text.AppendLine();
    }

    private static void AppendPerCategory(StringBuilder text, BenchmarkReport report)
    {
        text.AppendLine("## Per category");
        text.AppendLine();
        text.AppendLine("Precision / recall, with the number of judgeable observations behind them.");
        text.AppendLine();

        text.Append("| Category |");
        foreach (var tool in report.Tools) text.Append($" {tool} |");
        text.AppendLine();

        text.Append("|---|");
        foreach (var _ in report.Tools) text.Append("---|");
        text.AppendLine();

        foreach (var category in report.Categories)
        {
            text.Append($"| {category} |");

            foreach (var tool in report.Tools)
            {
                var score = report.For(tool, category);

                text.Append(score is null || score.Support == 0
                    // Nothing to judge: neither the corpus nor the tool put anything scoreable
                    // here. An em dash rather than "0%" — a zero would read as a failure to
                    // detect something, and there was nothing to detect.
                    ? " — |"
                    : $" {Percent(score.Precision)} / {Percent(score.Recall)} (n={score.Support}) |");
            }

            text.AppendLine();
        }

        text.AppendLine();
    }

    private static void AppendCaveats(StringBuilder text, BenchmarkReport report)
    {
        if (report.Caveats.Count == 0) return;

        text.AppendLine("## How to read this");
        text.AppendLine();

        foreach (var caveat in report.Caveats)
            text.AppendLine($"- {caveat}");

        text.AppendLine();
    }

    private static string Percent(double ratio) =>
        (ratio * 100).ToString("0.#", CultureInfo.InvariantCulture) + "%";
}

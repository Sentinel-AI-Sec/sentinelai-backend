namespace SentinelAI.Application.Features.Benchmark;

/// <summary>
/// SEC-39: classifies every tool's findings against the SEC-38 ground truth and computes
/// precision and recall per category, for every tool, over one shared corpus.
/// </summary>
/// <remarks>
/// <para>
/// <b>Pure, and deliberately so.</b> No database, no scanner, no file system, no clock. It takes
/// labels and findings and returns numbers, which means the arithmetic — which is the part that
/// gets quietly wrong — is unit-testable without a corpus, a Snyk licence or a SonarQube server.
/// Producing the inputs is <c>SentinelAI.Benchmark</c>'s job; getting them right is this class's.
/// </para>
/// <para>
/// <b>Matching is (project, file, category, line-within-window).</b> All four, because dropping
/// any one of them makes the score mean something else: without the project, two corpus projects
/// with an <c>infra/main.tf</c> cross-contaminate; without the category, a tool that reported a
/// logging warning where the label records an IAM escalation is credited with finding it, which
/// is the single easiest way to manufacture a good recall number.
/// </para>
/// <para>
/// <b>One label is credited to at most one report and vice versa.</b> Tools emit several rules
/// against the same weakness — Checkov alone reports a wildcard IAM policy under more than one
/// check id — and counting each as a separate true positive would multiply one detection into
/// several. Matching is therefore a greedy one-to-one pairing, nearest line first.
/// </para>
/// </remarks>
public static class BenchmarkScorer
{
    /// <summary>
    /// Scores every tool present in <paramref name="findings"/> against <paramref name="labels"/>.
    /// </summary>
    /// <param name="corpus">Corpus name and version, for the report header.</param>
    /// <param name="labels">The SEC-38 ground truth. Both polarities — see <see cref="GroundTruthLabel"/>.</param>
    /// <param name="findings">Every tool's normalised output over the same corpus.</param>
    /// <param name="window">Line tolerance. Defaults to <see cref="MatchWindow.Default"/>.</param>
    /// <param name="tools">
    /// Tools to report, even when one produced no findings at all. Defaults to
    /// <see cref="BenchmarkTools.Compared"/> unioned with whatever actually appeared — so a tool
    /// that ran and found nothing is a visible row of zeroes rather than an absent column that
    /// reads as "not measured".
    /// </param>
    public static BenchmarkReport Score(
        string corpus,
        IReadOnlyList<GroundTruthLabel> labels,
        IReadOnlyList<ToolFinding> findings,
        MatchWindow? window = null,
        IReadOnlyList<string>? tools = null)
    {
        ArgumentNullException.ThrowIfNull(labels);
        ArgumentNullException.ThrowIfNull(findings);

        var matchWindow = window ?? MatchWindow.Default;

        var reported = tools
            ?? [.. BenchmarkTools.Compared
                .Union(findings.Select(f => f.Tool), StringComparer.OrdinalIgnoreCase)];

        var scores = new List<CategoryScore>();

        foreach (var tool in reported)
        {
            var mine = findings
                .Where(f => string.Equals(f.Tool, tool, StringComparison.OrdinalIgnoreCase))
                .ToList();

            var classified = Classify(labels, mine, matchWindow);

            foreach (var category in Categories(labels, mine))
                scores.Add(ScoreOf(tool, category, classified, category));

            scores.Add(ScoreOf(tool, CategoryScore.AllCategories, classified, category: null));
        }

        return new BenchmarkReport(corpus, matchWindow, scores, Caveats(labels, findings, matchWindow));
    }

    /// <summary>The outcome of matching one tool's findings against the labels.</summary>
    private sealed record Classification(
        IReadOnlyList<(GroundTruthLabel Label, ToolFinding Finding)> Matched,
        IReadOnlyList<GroundTruthLabel> UnmatchedVulnerableLabels,
        IReadOnlyList<ToolFinding> UnmatchedFindings);

    /// <summary>
    /// Greedy nearest-line one-to-one pairing between labels and one tool's findings.
    /// </summary>
    /// <remarks>
    /// Greedy rather than optimal. A maximum-weight bipartite matching would differ only where
    /// two labels and two findings sit within the window of each other in the same file and
    /// category — a configuration the corpus does not contain, because two labels that close
    /// together are one weakness recorded twice. Paying for an assignment algorithm to break a
    /// tie that means "the corpus is mislabelled" would be the wrong trade.
    /// </remarks>
    private static Classification Classify(
        IReadOnlyList<GroundTruthLabel> labels, IReadOnlyList<ToolFinding> findings, MatchWindow window)
    {
        var matched = new List<(GroundTruthLabel, ToolFinding)>();
        var claimedFindings = new HashSet<ToolFinding>();
        var claimedLabels = new HashSet<GroundTruthLabel>();

        // Ordered so the result does not depend on the order the corpus files happened to be
        // read in: a benchmark whose numbers move when a directory listing changes is not a
        // benchmark.
        foreach (var label in labels.OrderBy(l => l.Project, StringComparer.Ordinal)
                     .ThenBy(l => l.File, StringComparer.Ordinal)
                     .ThenBy(l => l.Line)
                     .ThenBy(l => l.Id, StringComparer.Ordinal))
        {
            var candidate = findings
                .Where(f => !claimedFindings.Contains(f))
                .Where(f => IsSamePlace(label, f, window))
                .OrderBy(f => label.Line == 0 || f.Line == 0 ? 0 : Math.Abs(label.Line - f.Line))
                .ThenBy(f => f.Line)
                .ThenBy(f => f.RuleId, StringComparer.Ordinal)
                .FirstOrDefault();

            if (candidate is null) continue;

            claimedFindings.Add(candidate);
            claimedLabels.Add(label);
            matched.Add((label, candidate));
        }

        return new Classification(
            matched,
            [.. labels.Where(l => l.IsVulnerable && !claimedLabels.Contains(l))],
            [.. findings.Where(f => !claimedFindings.Contains(f))]);
    }

    private static bool IsSamePlace(GroundTruthLabel label, ToolFinding finding, MatchWindow window) =>
        string.Equals(label.Project, finding.Project, StringComparison.OrdinalIgnoreCase)
        && PathsMatch(label.File, finding.File)
        && string.Equals(label.Category, finding.Category, StringComparison.OrdinalIgnoreCase)
        && window.Covers(label.Line, finding.Line);

    /// <summary>
    /// Compares two repository-relative paths.
    /// </summary>
    /// <remarks>
    /// Separators are normalised because the three tools disagree: Checkov emits forward
    /// slashes, a Windows-run SonarQube scanner can emit backslashes, and a label file is
    /// written by hand. A path comparison that treats <c>infra\main.tf</c> and
    /// <c>infra/main.tf</c> as different files scores every finding on that file as unlabelled,
    /// silently, and the tool comes out with perfect precision over nothing.
    /// </remarks>
    private static bool PathsMatch(string left, string right) => string.Equals(
        left.Replace('\\', '/').TrimStart('.', '/'),
        right.Replace('\\', '/').TrimStart('.', '/'),
        StringComparison.OrdinalIgnoreCase);

    /// <summary>Every category that appears in the labels or in this tool's findings.</summary>
    /// <remarks>
    /// Both sides, not just the labels. A category a tool reports and the corpus never labels
    /// produces a row of zeroes with a non-zero unlabelled count — which is the visible form of
    /// "this tool is looking for something we cannot score", and worth seeing.
    /// </remarks>
    private static IEnumerable<string> Categories(
        IReadOnlyList<GroundTruthLabel> labels, IReadOnlyList<ToolFinding> findings) =>
        labels.Select(l => l.Category)
            .Concat(findings.Select(f => f.Category))
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(c => c, StringComparer.OrdinalIgnoreCase);

    /// <param name="category">Null for the overall row, which counts every category together.</param>
    private static CategoryScore ScoreOf(
        string tool, string label, Classification classified, string? category)
    {
        bool InCategory(string value) =>
            category is null || string.Equals(value, category, StringComparison.OrdinalIgnoreCase);

        var inScope = classified.Matched.Where(m => InCategory(m.Label.Category)).ToList();

        return new CategoryScore(
            Tool: tool,
            Category: label,
            TruePositives: inScope.Count(m => m.Label.IsVulnerable),
            FalsePositives: inScope.Count(m => !m.Label.IsVulnerable),
            FalseNegatives: classified.UnmatchedVulnerableLabels.Count(l => InCategory(l.Category)),
            Unlabelled: classified.UnmatchedFindings.Count(f => InCategory(f.Category)));
    }

    /// <summary>
    /// What the numbers cannot say about themselves.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>These are generated from the data, not written into the report by hand.</b> A caveat
    /// someone typed once goes stale the first time the corpus changes; one computed from the
    /// labels stays true, and appears only when it is.
    /// </para>
    /// <para>
    /// The C# one is the load-bearing case and SEC-38 names it explicitly: there is no C# OWASP
    /// Benchmark, so the C# ground truth is small and hand-labelled, and any C# figure here
    /// rests on a handful of labels one team wrote. A precision of 100% over six labels is not
    /// the same claim as 100% over six hundred, and a reader who is not told cannot tell.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<string> Caveats(
        IReadOnlyList<GroundTruthLabel> labels, IReadOnlyList<ToolFinding> findings, MatchWindow window)
    {
        var caveats = new List<string>
        {
            $"A report and a label are the same issue when they agree on project, file and "
            + $"category, and their lines are within {window}. Tools disagree on which line of a "
            + "block a finding belongs to, so exact-line matching would measure numbering "
            + "convention rather than detection.",

            "Findings at places the corpus does not label are excluded from precision entirely — "
            + "they are neither true nor false positives. The count is reported beside every "
            + "ratio because a tool with many unlabelled findings can hold a high precision over "
            + "very little.",
        };

        // The C# gap, stated with the number behind it rather than as a slogan.
        var csharpLabels = labels
            .Where(l => l.File.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (csharpLabels.Count > 0)
        {
            caveats.Add(
                $"C# ground truth is {csharpLabels.Count} hand-labelled location(s) across "
                + $"{csharpLabels.Select(l => l.Project).Distinct(StringComparer.OrdinalIgnoreCase).Count()} "
                + "project(s). No C# OWASP Benchmark exists, so unlike the Terraform corpora "
                + "these labels are this team's judgement rather than a published reference. Any "
                + "C# row below rests on that, and its confidence interval is wide.");
        }

        var unlabelledProjects = findings
            .Select(f => f.Project)
            .Except(labels.Select(l => l.Project), StringComparer.OrdinalIgnoreCase)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (unlabelledProjects.Count > 0)
        {
            caveats.Add(
                $"{unlabelledProjects.Count} project(s) were scanned but carry no labels at all "
                + $"({string.Join(", ", unlabelledProjects.Order(StringComparer.OrdinalIgnoreCase))}). "
                + "Every finding in them is unlabelled and contributes to no ratio.");
        }

        var thin = labels
            .Where(l => l.IsVulnerable)
            .GroupBy(l => l.Category, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() < 5)
            .Select(g => $"{g.Key} ({g.Count()})")
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (thin.Count > 0)
        {
            caveats.Add(
                "Categories with fewer than five vulnerable labels are reported but should not be "
                + $"compared between tools: {string.Join(", ", thin)}. One disagreement moves such "
                + "a figure by twenty points or more.");
        }

        return caveats;
    }
}

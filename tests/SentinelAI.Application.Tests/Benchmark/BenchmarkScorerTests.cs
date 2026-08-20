using SentinelAI.Application.Features.Benchmark;

namespace SentinelAI.Application.Tests.Benchmark;

/// <summary>
/// SEC-39's arithmetic: TP/FP/FN classification against the SEC-38 ground truth, and precision
/// and recall per category for every tool over one shared corpus.
/// </summary>
/// <remarks>
/// These run without a corpus, a Snyk licence or a SonarQube server, which is the reason the
/// scorer is a pure function in the first place. What cannot be tested here is whether the
/// corpus's labels are correct; that is SEC-38's problem and a human's.
/// </remarks>
public class BenchmarkScorerTests
{
    private const string Corpus = "test-corpus v1";

    private static GroundTruthLabel Vulnerable(
        string id, string category, int line, string file = "infra/main.tf", string project = "terragoat") =>
        new(id, project, file, line, category, IsVulnerable: true);

    private static GroundTruthLabel Clean(
        string id, string category, int line, string file = "infra/main.tf", string project = "terragoat") =>
        new(id, project, file, line, category, IsVulnerable: false);

    private static ToolFinding Reported(
        string tool, string category, int line, string file = "infra/main.tf", string project = "terragoat") =>
        new(tool, project, file, line, category, RuleId: $"{tool}-rule");

    // ---- classification --------------------------------------------------------------------

    /// <summary>A report on a vulnerable label is a true positive.</summary>
    [Fact]
    public void A_report_matching_a_vulnerable_label_is_a_true_positive()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Vulnerable("iam-01", "CWE-284", 25)],
            [Reported(BenchmarkTools.SentinelAi, "CWE-284", 25)]);

        var score = report.For(BenchmarkTools.SentinelAi, "CWE-284")!;

        Assert.Equal(1, score.TruePositives);
        Assert.Equal(0, score.FalsePositives);
        Assert.Equal(0, score.FalseNegatives);
        Assert.Equal(1d, score.Precision);
        Assert.Equal(1d, score.Recall);
    }

    /// <summary>
    /// A report on a place the corpus labelled <em>clean</em> is a false positive.
    /// </summary>
    /// <remarks>
    /// This is the assertion the whole clean half of the corpus exists for. Without labels that
    /// say "nothing is wrong here", a false positive is indistinguishable from a finding the
    /// labellers had not reached, and precision cannot be measured at all.
    /// </remarks>
    [Fact]
    public void A_report_matching_a_clean_label_is_a_false_positive()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Clean("clean-01", "CWE-284", 40)],
            [Reported(BenchmarkTools.SonarQube, "CWE-284", 40)]);

        var score = report.For(BenchmarkTools.SonarQube, "CWE-284")!;

        Assert.Equal(0, score.TruePositives);
        Assert.Equal(1, score.FalsePositives);
        Assert.Equal(0d, score.Precision);
    }

    /// <summary>A vulnerable label nobody reported is a false negative.</summary>
    [Fact]
    public void A_vulnerable_label_no_tool_reported_is_a_false_negative()
    {
        var report = BenchmarkScorer.Score(Corpus, [Vulnerable("iam-01", "CWE-284", 25)], []);

        var score = report.For(BenchmarkTools.Snyk, "CWE-284")!;

        Assert.Equal(1, score.FalseNegatives);
        Assert.Equal(0d, score.Recall);

        // Precision is 1, not 0: a tool that reported nothing has said nothing false. Recall is
        // where silence is punished, and that division of labour is the point of reporting both.
        Assert.Equal(1d, score.Precision);
    }

    /// <summary>
    /// A report at a place with no label at all is neither a true nor a false positive.
    /// </summary>
    /// <remarks>
    /// The single most consequential decision in the scorer. Counting these as false positives
    /// would punish the tool that looks hardest and would turn precision into a measure of how
    /// completely the corpus was labelled — so they are excluded, and the count is carried
    /// beside the ratio so nobody can quote 100% precision over nothing without seeing it.
    /// </remarks>
    [Fact]
    public void An_unlabelled_report_is_excluded_from_precision_and_counted_separately()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Vulnerable("iam-01", "CWE-284", 25)],
            [
                Reported(BenchmarkTools.SentinelAi, "CWE-284", 25),
                Reported(BenchmarkTools.SentinelAi, "CWE-284", 900),
            ]);

        var score = report.For(BenchmarkTools.SentinelAi, "CWE-284")!;

        Assert.Equal(1, score.TruePositives);
        Assert.Equal(0, score.FalsePositives);
        Assert.Equal(1, score.Unlabelled);
        Assert.Equal(1d, score.Precision);
    }

    // ---- matching --------------------------------------------------------------------------

    /// <summary>
    /// Lines within the window are the same issue; lines outside it are not.
    /// </summary>
    /// <remarks>
    /// Checkov reports a misconfiguration at the offending attribute and Snyk at the enclosing
    /// resource block. Exact-line matching would score one of them as having missed an issue it
    /// found, making recall a measure of numbering convention.
    /// </remarks>
    [Theory]
    [InlineData(25, true)]
    [InlineData(27, true)]
    [InlineData(28, true)]
    [InlineData(29, false)]
    public void A_report_within_the_line_window_matches_and_one_outside_it_does_not(int line, bool matches)
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Vulnerable("iam-01", "CWE-284", 25)],
            [Reported(BenchmarkTools.SentinelAi, "CWE-284", line)]);

        var score = report.For(BenchmarkTools.SentinelAi, "CWE-284")!;

        Assert.Equal(matches ? 1 : 0, score.TruePositives);
        Assert.Equal(matches ? 0 : 1, score.FalseNegatives);
    }

    /// <summary>
    /// The category has to agree, or a tool is credited with finding something else.
    /// </summary>
    /// <remarks>
    /// The easiest way to manufacture a good recall number is to match on location alone: a
    /// logging warning reported on the same line as an IAM escalation then counts as having
    /// found it.
    /// </remarks>
    [Fact]
    public void A_report_of_a_different_weakness_at_the_same_place_is_not_a_match()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Vulnerable("iam-01", "CWE-284", 25)],
            [Reported(BenchmarkTools.SentinelAi, "CWE-778", 25)]);

        Assert.Equal(1, report.For(BenchmarkTools.SentinelAi, "CWE-284")!.FalseNegatives);
        Assert.Equal(1, report.For(BenchmarkTools.SentinelAi, "CWE-778")!.Unlabelled);
    }

    /// <summary>Two corpus projects with the same file path do not cross-contaminate.</summary>
    [Fact]
    public void A_report_in_another_project_does_not_match_a_label()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Vulnerable("iam-01", "CWE-284", 25, project: "terragoat")],
            [Reported(BenchmarkTools.SentinelAi, "CWE-284", 25, project: "cfngoat")]);

        Assert.Equal(1, report.For(BenchmarkTools.SentinelAi, "CWE-284")!.FalseNegatives);
    }

    /// <summary>
    /// Two rules firing on one weakness count as one detection, not two.
    /// </summary>
    /// <remarks>
    /// Checkov alone reports a wildcard IAM policy under more than one check id. Without
    /// one-to-one pairing, a tool with more rules per weakness would out-score one with fewer
    /// while detecting exactly the same things.
    /// </remarks>
    [Fact]
    public void Two_reports_on_one_label_count_as_one_detection()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Vulnerable("iam-01", "CWE-284", 25)],
            [
                Reported(BenchmarkTools.SentinelAi, "CWE-284", 25),
                Reported(BenchmarkTools.SentinelAi, "CWE-284", 26),
            ]);

        var score = report.For(BenchmarkTools.SentinelAi, "CWE-284")!;

        Assert.Equal(1, score.TruePositives);
        Assert.Equal(1, score.Unlabelled);
    }

    /// <summary>A file-level label (line 0) matches a report anywhere in that file.</summary>
    [Fact]
    public void A_file_level_label_matches_a_report_anywhere_in_the_file()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Vulnerable("dockerfile-01", "CWE-250", line: 0, file: "Dockerfile")],
            [Reported(BenchmarkTools.Snyk, "CWE-250", line: 312, file: "Dockerfile")]);

        Assert.Equal(1, report.For(BenchmarkTools.Snyk, "CWE-250")!.TruePositives);
    }

    /// <summary>Windows and POSIX spellings of one path are one path.</summary>
    [Fact]
    public void Path_separators_do_not_split_one_file_into_two()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Vulnerable("iam-01", "CWE-284", 25, file: "infra/iam.tf")],
            [Reported(BenchmarkTools.SonarQube, "CWE-284", 25, file: @"infra\iam.tf")]);

        Assert.Equal(1, report.For(BenchmarkTools.SonarQube, "CWE-284")!.TruePositives);
    }

    // ---- the report ------------------------------------------------------------------------

    /// <summary>
    /// The acceptance criterion: one corpus, three tools, precision and recall per category.
    /// </summary>
    [Fact]
    public void The_shared_corpus_yields_precision_and_recall_per_category_for_all_three_tools()
    {
        var labels = new List<GroundTruthLabel>
        {
            Vulnerable("iam-01", "CWE-284", 25, "infra/iam.tf"),
            Vulnerable("iam-02", "CWE-284", 60, "infra/iam.tf"),
            Vulnerable("log-01", "CWE-778", 3, "infra/s3.tf"),
            Clean("clean-01", "CWE-284", 120, "infra/iam.tf"),
        };

        var findings = new List<ToolFinding>
        {
            // SentinelAI: both IAM issues, the logging one, and one false positive.
            Reported(BenchmarkTools.SentinelAi, "CWE-284", 25, "infra/iam.tf"),
            Reported(BenchmarkTools.SentinelAi, "CWE-284", 60, "infra/iam.tf"),
            Reported(BenchmarkTools.SentinelAi, "CWE-778", 3, "infra/s3.tf"),
            Reported(BenchmarkTools.SentinelAi, "CWE-284", 120, "infra/iam.tf"),

            // SonarQube: one IAM issue, nothing else.
            Reported(BenchmarkTools.SonarQube, "CWE-284", 25, "infra/iam.tf"),

            // Snyk: the logging issue only.
            Reported(BenchmarkTools.Snyk, "CWE-778", 3, "infra/s3.tf"),
        };

        var report = BenchmarkScorer.Score(Corpus, labels, findings);

        Assert.Equal(BenchmarkTools.Compared, report.Tools);
        Assert.Equal(["CWE-284", "CWE-778"], report.Categories);

        // SentinelAI found all three real issues and one thing that is not: recall 1, precision
        // 3/4.
        var ours = report.Overall(BenchmarkTools.SentinelAi)!;
        Assert.Equal(1d, ours.Recall);
        Assert.Equal(0.75d, ours.Precision);

        // SonarQube reported nothing false but found one of three.
        var sonar = report.Overall(BenchmarkTools.SonarQube)!;
        Assert.Equal(1d, sonar.Precision);
        Assert.Equal(1d / 3, sonar.Recall, precision: 6);

        // Per category is where the difference actually lives: Snyk has perfect recall on
        // logging and none on access control, which the overall row alone would hide.
        Assert.Equal(0d, report.For(BenchmarkTools.Snyk, "CWE-284")!.Recall);
        Assert.Equal(1d, report.For(BenchmarkTools.Snyk, "CWE-778")!.Recall);
    }

    /// <summary>
    /// A tool that was compared but produced nothing still gets a row.
    /// </summary>
    /// <remarks>
    /// An absent column reads as "not measured". "We ran it and it found nothing" is a result
    /// and belongs in the table.
    /// </remarks>
    [Fact]
    public void A_tool_that_reported_nothing_is_a_row_of_zeroes_not_an_absent_column()
    {
        var report = BenchmarkScorer.Score(Corpus, [Vulnerable("iam-01", "CWE-284", 25)], []);

        Assert.Equal(BenchmarkTools.Compared, report.Tools);
        Assert.All(BenchmarkTools.Compared, tool => Assert.NotNull(report.Overall(tool)));
    }

    // ---- caveats ---------------------------------------------------------------------------

    /// <summary>
    /// The C# ground-truth gap is stated in the report, with its size.
    /// </summary>
    /// <remarks>
    /// SEC-38's acceptance criterion is that the limited C# ground truth is "stated, not papered
    /// over". Generated from the labels rather than typed in once, so it stays true as the
    /// corpus grows and disappears if a real C# benchmark ever arrives.
    /// </remarks>
    [Fact]
    public void The_csharp_ground_truth_gap_is_stated_with_the_number_behind_it()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [
                Vulnerable("cs-01", "CWE-502", 41, "src/OrderApp/Controllers/OrdersController.cs", "fixture"),
                Vulnerable("cs-02", "CWE-89", 12, "src/OrderApp/Data/Repo.cs", "fixture"),
            ],
            []);

        var caveat = Assert.Single(report.Caveats, c => c.Contains("C# ground truth"));

        Assert.Contains("2 hand-labelled location(s)", caveat);
        Assert.Contains("No C# OWASP Benchmark exists", caveat);
    }

    /// <summary>A corpus with no C# labels does not carry a C# caveat.</summary>
    /// <remarks>
    /// A caveat that always appears is one nobody reads. It is generated from the data so it
    /// means something when it is there.
    /// </remarks>
    [Fact]
    public void A_corpus_with_no_csharp_labels_carries_no_csharp_caveat()
    {
        var report = BenchmarkScorer.Score(Corpus, [Vulnerable("iam-01", "CWE-284", 25)], []);

        Assert.DoesNotContain(report.Caveats, c => c.Contains("C# ground truth"));
    }

    /// <summary>Categories too thin to compare between tools say so.</summary>
    [Fact]
    public void A_category_with_too_few_labels_is_flagged_as_not_comparable()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Vulnerable("iam-01", "CWE-284", 25), Vulnerable("iam-02", "CWE-284", 60)],
            []);

        Assert.Single(report.Caveats, c => c.Contains("fewer than five vulnerable labels")
            && c.Contains("CWE-284 (2)"));
    }

    /// <summary>A scanned project the corpus never labelled is named, not silently ignored.</summary>
    [Fact]
    public void A_project_with_no_labels_at_all_is_named_in_the_caveats()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Vulnerable("iam-01", "CWE-284", 25, project: "terragoat")],
            [Reported(BenchmarkTools.Snyk, "CWE-284", 25, project: "kubernetes-goat")]);

        Assert.Single(report.Caveats, c => c.Contains("kubernetes-goat") && c.Contains("no labels at all"));
    }

    // ---- rendering ---------------------------------------------------------------------------

    /// <summary>
    /// Precision and recall reach the reader together, with the counts behind them.
    /// </summary>
    /// <remarks>
    /// SEC-39 asks for both "together" for a reason: either can be bought with the other. A
    /// layout that let one be read alone would make the wrong number the quotable one.
    /// </remarks>
    [Fact]
    public void The_markdown_report_pairs_precision_with_recall_and_shows_its_support()
    {
        var report = BenchmarkScorer.Score(
            Corpus,
            [Vulnerable("iam-01", "CWE-284", 25), Clean("clean-01", "CWE-284", 120)],
            [
                Reported(BenchmarkTools.SentinelAi, "CWE-284", 25),
                Reported(BenchmarkTools.SentinelAi, "CWE-284", 120),
            ]);

        var markdown = BenchmarkReportRenderer.ToMarkdown(report);

        Assert.Contains("| Tool | Precision | Recall | F1 | TP | FP | FN | Unlabelled |", markdown);
        Assert.Contains("50% / 100% (n=2)", markdown);
        Assert.Contains("test-corpus v1", markdown);
        Assert.Contains("±3 lines", markdown);
        Assert.Contains("How to read this", markdown);
    }
}

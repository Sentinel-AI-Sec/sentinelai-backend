using SentinelAI.Integration.Tests.Handoff;

namespace SentinelAI.Integration.Tests.Regression;

/// <summary>
/// Keeps <c>samples/golden-bundle/</c> honest against the fixture repository it was copied from.
/// </summary>
/// <remarks>
/// <para>
/// <b>The hazard this closes has already happened here.</b> For one sprint
/// <c>FlagshipChainTests</c> asserted the flagship chain over a Dockerfile carrying
/// <c>LABEL org.sentinelai.image</c> that the real fixture did not have. Every assertion passed
/// and the product was broken the whole time, because a copy cannot drift from the code but it
/// drifts from the fixture — and nothing was comparing the two.
/// </para>
/// <para>
/// <b>Why a copy exists.</b> The fixtures are a sibling repository, not a submodule, so a
/// backend-only checkout — which is what CI does — has none of them. A regression harness that
/// skipped there would never run on the change that broke something. The copy makes the harness
/// unconditional; this file makes the copy verifiable. Where the fixture is checked out, drift
/// fails loudly; where it is not, this skips with a stated reason and the harness still runs.
/// </para>
/// <para>
/// <b>Containment, not equality, and the reason is not convenience.</b> The golden bundle is the
/// fixture <em>trimmed to the blocks that carry the chain</em> — its <c>legacy.tf</c> is an
/// extract of the fixture's <c>main.tf</c>, and its <c>main.tf</c> is the order-task half of the
/// same file. Requiring equality would fail permanently for a reason that has nothing to do with
/// drift, and a permanently red check is one nobody reads, which is worse than not having it.
/// What is checked is that every meaningful line of the copy still appears in the original: that
/// catches a renamed resource, a removed label, a changed image coordinate or a moved policy
/// block, which is the entire class of drift that has ever hurt here.
/// </para>
/// <para>
/// Blank lines and comment-only lines are ignored, and surrounding whitespace is trimmed, so a
/// Windows checkout and a Linux runner agree.
/// </para>
/// </remarks>
public class FixtureParityTests
{
    /// <summary>
    /// Every file the golden bundle copies still matches the fixture's own.
    /// </summary>
    /// <remarks>
    /// One test over all of them rather than one per file, because the useful failure message is
    /// the whole list: a fixture that moved usually moved in more than one place, and being told
    /// about the first file only means finding the rest one CI run at a time.
    /// </remarks>
    [CommittedFixtureFact]
    public void The_golden_bundle_still_matches_the_fixture_repository()
    {
        var root = FixtureRepo.Require();
        var drifted = new List<string>();

        foreach (var (copyPath, fixturePaths) in GoldenBundle.FixtureSources)
        {
            var originals = fixturePaths
                .Select(p => (Relative: p, Full: Path.Combine(root, p.Replace('/', Path.DirectorySeparatorChar))))
                .ToList();

            var absent = originals.Where(o => !File.Exists(o.Full)).Select(o => o.Relative).ToList();

            if (absent.Count > 0)
            {
                drifted.Add(
                    $"{copyPath}: {string.Join(", ", absent.Select(a => $"'{a}'"))} "
                    + $"{(absent.Count == 1 ? "is" : "are")} not in the fixture repository");
                continue;
            }

            // The union of every named original. A copy that draws a block from one file and a
            // block from another is still a faithful copy; what would not be faithful is a line
            // that appears in none of them.
            var fixtureLines = originals
                .SelectMany(o => Meaningful(File.ReadAllText(o.Full)))
                .ToHashSet(StringComparer.Ordinal);

            var missing = Meaningful(GoldenBundle.Read(copyPath))
                .Where(line => !fixtureLines.Contains(line))
                .ToList();

            if (missing.Count > 0)
            {
                drifted.Add(
                    $"{copyPath}: {missing.Count} line(s) are not in "
                    + $"{string.Join(" / ", fixturePaths.Select(p => $"'{p}'"))} — first is "
                    + $"'{missing[0]}'");
            }
        }

        Assert.True(
            drifted.Count == 0,
            $"the golden bundle has drifted from {root}:{Environment.NewLine}  "
            + string.Join($"{Environment.NewLine}  ", drifted)
            + $"{Environment.NewLine}{Environment.NewLine}"
            + "Update samples/golden-bundle to match the fixture — or, if the fixture changed by "
            + "mistake, update the fixture. What must not happen is the harness continuing to "
            + "assert against bytes the scanners never saw.");
    }

    /// <summary>
    /// The fixture's <c>infra/iam.tf</c> still puts the flagship policy at line 25.
    /// </summary>
    /// <remarks>
    /// The line number is not incidental. <c>TerraformFindingLocator</c> joins a scanner's
    /// <c>file:line</c> to the Terraform block containing it, so if the fixture's <c>iam.tf</c>
    /// gains or loses a comment line, the flagship finding stops landing on
    /// <c>iam_role:order_task_role</c> and the chain loses its seed — with no error anywhere,
    /// just one fewer candidate. Both files are checked, because the copy's own line 25 is what
    /// <c>findings/checkov.sarif</c> points at.
    /// </remarks>
    [CommittedFixtureFact]
    public void The_flagship_policy_is_still_at_line_25_in_both_copies()
    {
        AssertPolicyAtLine25(File.ReadAllLines(Path.Combine(FixtureRepo.Require(), "infra", "iam.tf")), "the fixture");
        AssertPolicyAtLine25(GoldenBundle.Read("graph-inputs/infra/iam.tf").ReplaceLineEndings("\n").Split('\n'), "the golden bundle");
    }

    private static void AssertPolicyAtLine25(string[] lines, string which)
    {
        Assert.True(lines.Length >= 25, $"{which}'s infra/iam.tf has only {lines.Length} lines");

        Assert.Contains(
            "aws_iam_role_policy",
            lines[24]);
    }

    /// <summary>
    /// Lines that carry meaning: not blank, not a whole-line comment, trimmed.
    /// </summary>
    /// <remarks>
    /// Comments are excluded because the fixture's are documentation for a human reading it and
    /// move independently of the resources. The one comment that <em>is</em> load-bearing — the
    /// block that puts the IAM policy on line 25 — is covered by its own test above, where the
    /// property being checked is a line number rather than a text.
    /// </remarks>
    private static IEnumerable<string> Meaningful(string text) =>
        text.ReplaceLineEndings()
            .Split(Environment.NewLine)
            .Select(Normalize)
            .Where(line => line.Length > 0 && !line.StartsWith('#') && !line.StartsWith("//"));

    /// <summary>
    /// One line, reduced to what it means.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The trailing comma is the reason this exists. <c>packages.lock.json</c> in the bundle is a
    /// <em>subset</em> of the fixture's, and the last entry of a JSON object cannot keep the comma
    /// the fixture's copy has after it — the file would not parse, and the scanners have to parse
    /// it. So <c>"resolved": "12.0.1"</c> here and <c>"resolved": "12.0.1",</c> there are the same
    /// line, and reporting them as drift is reporting the trim itself.
    /// </para>
    /// <para>
    /// Nothing else is normalized. Internal alignment is left alone deliberately: collapsing it
    /// would also hide a changed value, and the copies are verbatim extracts, so they have no
    /// reason to be aligned differently.
    /// </para>
    /// </remarks>
    private static string Normalize(string line) => line.Trim().TrimEnd(',');
}

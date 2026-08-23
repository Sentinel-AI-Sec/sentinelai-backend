using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Regression;

/// <summary>
/// SEC-49 — the full-flow regression harness, asserted.
/// </summary>
/// <remarks>
/// <para>
/// The acceptance criteria, one test each:
/// </para>
/// <list type="bullet">
/// <item><description>the fixture's three-layer chain reconstructs end to end;</description></item>
/// <item><description>per-layer finding counts are exactly what the fixture implies;</description></item>
/// <item><description>every retrieval mode fires;</description></item>
/// <item><description>edges are oriented in attack direction;</description></item>
/// <item><description>the expected cited path is present in what the read API serves;</description></item>
/// <item><description>and a broken stage is pinpointed rather than inferred.</description></item>
/// </list>
/// <para>
/// <b>One run, many assertions.</b> The flow takes a few seconds and is deterministic, so it is
/// executed once per class through <see cref="IAsyncLifetime"/> and every test reads the same
/// <see cref="FullFlowRun"/>. Running it per test would multiply the cost by six and could not
/// discover anything extra — the run has no state that varies between them.
/// </para>
/// <para>
/// <b>Every assertion carries <see cref="FullFlowRun.Diagnosis"/>.</b> That is not decoration:
/// SEC-49's second criterion is that a regression pinpoints its stage, and a pinpoint that does
/// not reach the CI log has not pinpointed anything for the person reading it.
/// </para>
/// </remarks>
public sealed class FullFlowRegressionTests : IClassFixture<ScanApiFactory>, IAsyncLifetime
{
    private readonly ScanApiFactory _factory;
    private FullFlowRun _run = null!;

    public FullFlowRegressionTests(ScanApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => _run = await new FullFlowHarness(_factory).RunAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// The headline: every stage produced what the next one needed.
    /// </summary>
    /// <remarks>
    /// Deliberately the first test in the file and the coarsest. When this is the only red one,
    /// the stage table in the message says where to look; when it is red alongside others, it is
    /// the one to read first.
    /// </remarks>
    [Fact]
    public void The_fixture_runs_end_to_end_through_every_stage()
    {
        Assert.True(_run.Succeeded, _run.Diagnosis);

        Assert.Equal(
            Enum.GetValues<FullFlowStage>(),
            [.. _run.Observations.Select(o => o.Stage)]);
    }

    /// <summary>
    /// Exact per-layer counts, not "at least one".
    /// </summary>
    /// <remarks>
    /// A harness that asserts non-emptiness passes on a run that lost two thirds of its
    /// findings. That is not hypothetical: routing only <c>osv.json</c> when the runner writes
    /// <c>osv.sarif</c> dropped an entire scanner's output, and the scan looked clean.
    /// </remarks>
    [Fact]
    public void Every_layer_contributes_the_findings_the_fixture_implies()
    {
        Assert.True(_run.Succeeded, _run.Diagnosis);

        foreach (var (layer, expected) in GoldenBundle.FindingsByLayer)
        {
            Assert.True(
                _run.FindingsByLayer.TryGetValue(layer, out var actual),
                $"no findings at all on the {layer} layer{_run.Diagnosis}");

            Assert.True(
                expected == actual,
                $"expected {expected} {layer} finding(s), got {actual}{_run.Diagnosis}");
        }
    }

    /// <summary>
    /// The flagship chain — dependency to code to task to role to crown jewel — reconstructs.
    /// </summary>
    /// <remarks>
    /// The whole product claim in one assertion. Every hop crosses a boundary a single-layer
    /// scanner cannot: the lock file joins the package to the project, the image label joins the
    /// project to the task definition, the task definition names its role, and the role's inline
    /// policy reaches the bucket.
    /// </remarks>
    [Fact]
    public void The_three_layer_flagship_chain_reconstructs()
    {
        Assert.True(_run.Succeeded, _run.Diagnosis);

        Assert.True(
            _run.ChainPaths.Any(path => path.SequenceEqual(GoldenBundle.FlagshipPath)),
            $"the flagship chain is not among the {_run.ChainPaths.Count} candidate(s). Expected"
            + $"{Environment.NewLine}  {string.Join(" -> ", GoldenBundle.FlagshipPath)}"
            + $"{Environment.NewLine}found{Environment.NewLine}  "
            + string.Join($"{Environment.NewLine}  ", _run.ChainPaths.Select(p => string.Join(" -> ", p)))
            + _run.Diagnosis);
    }

    /// <summary>
    /// All three arms of SEC-22's decision tree answered at least one finding.
    /// </summary>
    /// <remarks>
    /// A mode that never fires is either dead code or a tree that stopped branching, and neither
    /// shows up in a grounding-coverage number — 100% coverage with everything answered by the
    /// exact arm means the semantic half was never exercised, and the first id-less finding in
    /// production is the test.
    /// </remarks>
    [Fact]
    public void All_three_retrieval_modes_fire_over_the_fixture()
    {
        Assert.True(_run.Succeeded, _run.Diagnosis);

        var missing = new[] { "ExactFilter", "Semantic", "Hybrid" }
            .Except(_run.RetrievalModesThatFired, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"retrieval mode(s) that never fired: {string.Join(", ", missing)}{_run.Diagnosis}");
    }

    /// <summary>
    /// Every edge points the way an attacker moves, not the way Terraform builds.
    /// </summary>
    /// <remarks>
    /// <c>terraform graph</c> emits dependency order — the bucket depends on the policy, so its
    /// arrow points backwards from an attacker's perspective. Reversing that is
    /// <c>AttackDirectionOrienter</c>'s only job, and getting it wrong produces zero chains with
    /// no error anywhere: the graph is fully built, fully connected, and traversable only in the
    /// direction nothing is looking.
    /// </remarks>
    [Fact]
    public void Every_persisted_edge_is_oriented_in_attack_direction()
    {
        Assert.True(_run.Succeeded, _run.Diagnosis);

        var backwards = _run.Edges.Where(e => !e.Oriented).ToList();

        Assert.True(
            backwards.Count == 0,
            $"{backwards.Count} edge(s) are not oriented to attack direction: "
            + string.Join(", ", backwards.Select(e => $"{e.From} -{e.Relation}-> {e.To}"))
            + _run.Diagnosis);
    }

    /// <summary>
    /// The path the report leads with is the flagship path, and it is cited.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the seam that finding 42-A lived in: the backend writing one thing and the screen
    /// rendering another, each individually green. Asserting the chain as the <em>read API</em>
    /// serves it — not as the graph stage returned it — is what makes the two halves agree in a
    /// test rather than in a demo.
    /// </para>
    /// <para>
    /// Citations are asserted as non-empty rather than by id, because which chunks the corpus
    /// returns is the corpus's business. That the report rests on <em>something</em> retrievable
    /// is not: an audit with no citations is an assertion with nothing behind it.
    /// </para>
    /// </remarks>
    [Fact]
    public void The_expected_cited_path_is_present_in_what_the_read_api_serves()
    {
        Assert.True(_run.Succeeded, _run.Diagnosis);

        Assert.True(
            _run.ReportedChainPaths.Any(path => path.SequenceEqual(GoldenBundle.FlagshipPath)),
            $"the retained report does not serve the flagship path. It serves:"
            + $"{Environment.NewLine}  "
            + string.Join($"{Environment.NewLine}  ", _run.ReportedChainPaths.Select(p => string.Join(" -> ", p)))
            + _run.Diagnosis);

        Assert.True(_run.CitedChunkIds.Count > 0, $"the report cites nothing{_run.Diagnosis}");
    }

    /// <summary>
    /// The pinpoint itself works — a run that breaks names the stage it broke at.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SEC-49's second acceptance criterion is not "the fixture passes"; it is "a broken stage is
    /// pinpointed". That is a property of the harness, and a harness only ever run against a
    /// healthy fixture has never demonstrated it. So this asserts the machinery directly, on a
    /// synthetic run: the first failing stage is the one reported, later failures are not, and
    /// the diagnosis says so in words a reader can act on.
    /// </para>
    /// <para>
    /// Without this test the pinpoint is a feature nobody has run, which is the same category of
    /// unverified claim SEC-49 exists to eliminate.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_broken_stage_names_itself_and_the_stages_after_it_stay_silent()
    {
        var broken = new FullFlowRun
        {
            ScanJobId = Guid.Empty,
            Observations =
            [
                new(FullFlowStage.Ingest, true, "202 Accepted"),
                new(FullFlowStage.Normalize, true, "4 finding(s)"),
                new(FullFlowStage.Graph, false, "7 node(s) and no edges — the graph is islands"),
            ],
        };

        Assert.Equal(FullFlowStage.Graph, broken.BrokenStage);
        Assert.False(broken.Succeeded);

        Assert.Contains("BROKEN AT: Graph", broken.Diagnosis);
        Assert.Contains("the graph is islands", broken.Diagnosis);

        // The five stages the run never reached are named as unreached rather than left out,
        // so "not measured" cannot be read as "measured and fine".
        Assert.Contains("not reached: Chain, Retrieval, Debate, Report, ReadBack", broken.Diagnosis);
    }
}

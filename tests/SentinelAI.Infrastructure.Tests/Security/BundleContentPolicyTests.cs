using SentinelAI.Application.Features.Scan.Security;

namespace SentinelAI.Infrastructure.Tests.Security;

/// <summary>
/// SEC-34 box 2: the bundle contains the collector's artifacts and nothing else, so there is
/// no application source for the backend to process.
/// </summary>
/// <remarks>
/// The point of these tests is that the assertion <b>can fail</b>. Four guards already claim
/// this property — the runner's whitelist collector, two runs of <c>assert-no-source.sh</c>,
/// and the ingest inspector's extension denylist — and the repeated audit finding against
/// them is that nothing anyone runs demonstrates a rejection. Every negative case below is a
/// bundle that a real Action could plausibly produce.
/// </remarks>
public class BundleContentPolicyTests
{
    /// <summary>The shape a real bundle has, per <c>collect-graph-inputs.sh</c> and <c>run-scanners.sh</c>.</summary>
    private static readonly string[] RealBundleLayout =
    [
        "metadata.json",
        "scanner-versions.json",
        "findings/roslyn.sarif",
        "findings/osv.sarif",
        "findings/trivy.sarif",
        "findings/checkov_infra.sarif",
        "findings/checkov_docker.sarif",
        "graph-inputs/terraform-graph.dot",
        "graph-inputs/infra/main.tf",
        "graph-inputs/infra/iam.tf",
        "graph-inputs/Dockerfile",
        "graph-inputs/src/OrderApp/OrderApp.csproj",
        "graph-inputs/src/OrderApp/packages.lock.json",
    ];

    [Fact]
    public void A_real_bundle_layout_is_accepted()
    {
        var decision = BundleContentPolicy.Evaluate(RealBundleLayout);

        Assert.True(decision.IsAccepted, decision.Error);
        Assert.Empty(decision.SourceFiles);
        Assert.Empty(decision.OutsideLayout);
    }

    [Fact]
    public void Tar_style_leading_dot_slash_is_not_treated_as_a_violation()
    {
        // `tar -czf bundle.tar.gz -C dir .` writes every entry as ./name. A policy that did
        // not normalise would reject every real bundle and pass every hand-built test.
        var decision = BundleContentPolicy.Evaluate(
            [.. RealBundleLayout.Select(e => "./" + e)]);

        Assert.True(decision.IsAccepted, decision.Error);
    }

    [Fact]
    public void A_cs_file_is_rejected_and_reported_as_application_source()
    {
        var decision = BundleContentPolicy.Evaluate(
            ["metadata.json", "findings/roslyn.sarif", "src/OrderApp/Program.cs"]);

        Assert.False(decision.IsAccepted);
        Assert.Equal(["src/OrderApp/Program.cs"], decision.SourceFiles);
        Assert.Contains("application source", decision.Error);
    }

    /// <summary>
    /// The gap this policy exists for. The ingest inspector's denylist — and the Action's
    /// copy of the same list — spell out <c>ts</c>, <c>tsx</c> and <c>jsx</c> but not
    /// <c>js</c>, so an entire Node application passes every guard that ran before this one.
    /// </summary>
    [Theory]
    [InlineData("src/app/server.js")]
    [InlineData("src/app/index.mjs")]
    [InlineData("scripts/deploy.sh")]
    [InlineData("db/migrate.sql")]
    [InlineData("tools/build.ps1")]
    public void Source_extensions_the_upstream_denylist_omits_are_still_rejected(string entry)
    {
        var decision = BundleContentPolicy.Evaluate(["metadata.json", "findings/osv.sarif", entry]);

        Assert.False(decision.IsAccepted);
        Assert.Equal([entry], decision.SourceFiles);
        Assert.Contains("application source", decision.Error);
    }

    [Fact]
    public void Source_hidden_under_graph_inputs_is_still_source()
    {
        // The interesting case: it is inside the directory the collector owns, so a check
        // that only looked outside graph-inputs/ would wave it through.
        var decision = BundleContentPolicy.Evaluate(
            ["metadata.json", "findings/osv.sarif", "graph-inputs/src/OrderApp/Program.cs"]);

        Assert.False(decision.IsAccepted);
        Assert.Equal(BundleEntryKind.ApplicationSource,
            BundleContentPolicy.Classify("graph-inputs/src/OrderApp/Program.cs"));
        Assert.Contains("application source", decision.Error);
    }

    [Fact]
    public void A_file_that_is_not_source_but_is_not_in_the_contract_is_still_refused()
    {
        // Not source, not dangerous — and not something we have characterised either. "Bundle
        // only" is not a claim we can make while accepting arbitrary attachments.
        var decision = BundleContentPolicy.Evaluate(
            ["metadata.json", "findings/osv.sarif", "README.md", "gitleaks-report.json"]);

        Assert.False(decision.IsAccepted);
        Assert.Empty(decision.SourceFiles);
        Assert.Equal(["README.md", "gitleaks-report.json"], decision.OutsideLayout);
        Assert.Contains("outside the bundle contract", decision.Error);
    }

    [Fact]
    public void A_graph_input_outside_the_collector_whitelist_is_refused()
    {
        // appsettings.json is configuration, not a graph input, and it is where connection
        // strings live. The collector never copies it; if one arrives, something else did.
        var decision = BundleContentPolicy.Evaluate(
            ["metadata.json", "findings/osv.sarif", "graph-inputs/src/OrderApp/appsettings.json"]);

        Assert.False(decision.IsAccepted);
        Assert.Equal(["graph-inputs/src/OrderApp/appsettings.json"], decision.OutsideLayout);
    }

    [Theory]
    [InlineData("graph-inputs/infra/main.tf")]
    [InlineData("graph-inputs/infra/main.tf.json")]
    [InlineData("graph-inputs/Dockerfile")]
    [InlineData("graph-inputs/services/api/Dockerfile.prod")]
    [InlineData("graph-inputs/src/OrderApp/OrderApp.csproj")]
    [InlineData("graph-inputs/src/OrderApp/packages.lock.json")]
    [InlineData("graph-inputs/web/package-lock.json")]
    [InlineData("graph-inputs/terraform-graph.dot")]
    public void Every_pattern_the_collector_copies_is_allowed(string entry)
    {
        // If this list and collect-graph-inputs.sh ever disagree, real bundles start being
        // refused — which is the failure direction we want, but only if it is noticed here
        // first rather than in production.
        Assert.Equal(BundleEntryKind.Expected, BundleContentPolicy.Classify(entry));
    }

    [Fact]
    public void Source_is_reported_ahead_of_layout_when_a_bundle_has_both()
    {
        // The two rejections mean different things: source means the Action's guard failed,
        // a stray file means the contract drifted. The message has to say which.
        var decision = BundleContentPolicy.Evaluate(
            ["metadata.json", "findings/osv.sarif", "README.md", "src/Program.cs"]);

        Assert.False(decision.IsAccepted);
        Assert.Single(decision.SourceFiles);
        Assert.Single(decision.OutsideLayout);
        Assert.Contains("application source", decision.Error);
    }
}

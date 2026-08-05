using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Normalization;

namespace SentinelAI.Infrastructure.Tests.Normalization;

/// <summary>
/// SEC-16's three acceptance boxes, asserted against a bundle carrying <em>every</em> scanner in
/// the toolchain, arranged with the filenames <c>scripts/run-scanners.sh</c> actually writes.
/// </summary>
/// <remarks>
/// <para>
/// The filenames are the point. Every long-lived defect in this pipeline has lived in a seam
/// rather than inside a file — <c>osv.sarif</c> versus <c>osv.json</c>, <c>AVD-AWS-0089</c>
/// versus <c>AWS-0089</c>, <c>checkov_infra</c> versus <c>checkov-infra</c> — and none of them
/// was visible to a test that fed the pipeline names of its own choosing. So this test spells
/// them the way the runner does.
/// </para>
/// <para>
/// The sprint text says "five scanners". The toolchain is four: Semgrep and Dependency-Check
/// were dropped, replaced by Roslyn and OSV-Scanner. What the box means is <em>all of them</em>,
/// and that is what is asserted — including that no scanner contributes zero, which is how OSV
/// went missing.
/// </para>
/// </remarks>
public class UnifiedFindingsAcceptanceTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    /// <summary>Exactly the names <c>run-scanners.sh</c> writes into <c>bundle/findings/</c>.</summary>
    private static StubBundleStore WholeToolchain() => new()
    {
        ["findings/roslyn.sarif"] = Fixtures.RoslynSarifV2,
        ["findings/osv.sarif"] = Fixtures.OsvSarifV2,
        ["findings/trivy.sarif"] = Fixtures.TrivySarifV2,
        ["findings/checkov_infra.sarif"] = Fixtures.CheckovSarifV1,
        ["findings/checkov_docker.sarif"] = Fixtures.CheckovDockerSarifV2,
        ["metadata.json"] = "{}",
    };

    private static NormalizationPipeline Build(IBundleStore store)
    {
        IFindingExtractor[] extractors =
        [
            new RoslynSarifExtractor(), new OsvExtractor(),
            new TrivySarifExtractor(), new CheckovSarifExtractor(),
        ];

        var resolver = new RuleMappingResolver(
            new FakeRuleMappingLookup(), NullLogger<RuleMappingResolver>.Instance);

        return new NormalizationPipeline(
            extractors, store, resolver, new FindingUnifier(), NullLogger<NormalizationPipeline>.Instance);
    }

    private static Task<IReadOnlyList<Finding>> Normalize() =>
        Build(WholeToolchain()).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

    // ---- Box 1: findings from every scanner become one deduplicated list -------------------

    [Fact]
    public async Task Every_scanner_in_the_toolchain_contributes_to_the_one_list()
    {
        var findings = await Normalize();

        var byTool = findings.GroupBy(f => f.SourceTool).ToDictionary(g => g.Key, g => g.Count());

        string[] toolchain = [ScannerNames.Roslyn, ScannerNames.Osv, ScannerNames.Trivy, ScannerNames.Checkov];
        foreach (var tool in toolchain)
        {
            Assert.True(
                byTool.GetValueOrDefault(tool) > 0,
                $"{tool} contributed nothing to the unified set. A scanner that silently drops " +
                $"out looks exactly like a scanner that found nothing. Present: " +
                $"{string.Join(", ", byTool.Select(kv => $"{kv.Key}={kv.Value}"))}");
        }

        // All three layers reached the set — the graph needs all of them to build a chain.
        Assert.Contains(findings, f => f.Layer == Layer.Code);
        Assert.Contains(findings, f => f.Layer == Layer.Dep);
        Assert.Contains(findings, f => f.Layer == Layer.Infra);
    }

    [Fact]
    public async Task The_list_is_deduplicated()
    {
        var findings = await Normalize();

        var keys = findings
            .Select(f => (f.SourceTool, f.CheckId, f.CveId, f.Location, f.Message))
            .ToList();

        Assert.Equal(keys.Count, keys.Distinct().Count());
    }

    [Fact]
    public async Task One_scanner_reported_twice_collapses_but_distinct_problems_survive()
    {
        // The same bundle with checkov_infra delivered twice, as a runner re-run would produce.
        var store = WholeToolchain();
        var once = await Build(store).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        store["findings/checkov_infra_rerun.sarif"] = Fixtures.CheckovSarifV1;
        var twice = await Build(store).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        Assert.Equal(once.Count, twice.Count);
    }

    // ---- Box 2: every finding has consistent severity and layer tags -----------------------

    [Fact]
    public async Task Every_finding_carries_a_severity_on_the_one_scale()
    {
        var findings = await Normalize();

        Assert.All(findings, f => Assert.InRange(f.Severity, 0, 4));

        // Not all zero: a scale that never leaves its floor is not a scale. The fixtures carry
        // both "error" and "warning", so both ends must be represented.
        Assert.Contains(findings, f => f.Severity >= 4);
        Assert.Contains(findings, f => f.Severity is > 0 and < 4);
    }

    [Fact]
    public async Task Every_finding_carries_a_layer_consistent_with_its_tool()
    {
        var findings = await Normalize();

        Assert.All(findings, f => Assert.True(Enum.IsDefined(f.Layer), $"undefined layer on {f.SourceTool}/{f.CheckId}"));

        // The per-tool rule from SEC-14, restated here because it is what "consistent layer
        // tags" means across the unified set rather than within one extractor.
        Assert.All(findings.Where(f => f.SourceTool == ScannerNames.Roslyn), f => Assert.Equal(Layer.Code, f.Layer));
        Assert.All(findings.Where(f => f.SourceTool == ScannerNames.Osv), f => Assert.Equal(Layer.Dep, f.Layer));
        Assert.All(findings.Where(f => f.SourceTool == ScannerNames.Checkov), f => Assert.Equal(Layer.Infra, f.Layer));

        // Trivy is the one tool that straddles: a CVE means a dependency, anything else infra.
        Assert.All(
            findings.Where(f => f.SourceTool == ScannerNames.Trivy),
            f => Assert.Equal(f.CveId is not null ? Layer.Dep : Layer.Infra, f.Layer));
    }

    [Fact]
    public async Task A_findings_layer_agrees_with_the_type_of_node_it_decorates()
    {
        var findings = await Normalize();

        foreach (var finding in findings)
        {
            Assert.True(NodeId.TryParse(finding.NodeRef, out var type, out _), finding.NodeRef);

            var expected = finding.Layer switch
            {
                Layer.Dep => NodeType.Pkg,
                Layer.Infra => NodeType.Resource,
                _ => NodeType.Code,
            };

            Assert.Equal(expected, type);
        }
    }

    // ---- Box 3: every finding carries a node_ref in the canonical format -------------------

    [Fact]
    public async Task Every_finding_carries_a_canonical_node_reference()
    {
        var findings = await Normalize();

        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.False(string.IsNullOrWhiteSpace(f.NodeRef)));
        Assert.All(findings, f => Assert.True(
            NodeId.IsCanonical(f.NodeRef),
            $"'{f.NodeRef}' is not a key this codebase could have produced ({f.SourceTool}/{f.CheckId})"));
    }

    [Fact]
    public async Task Node_references_are_machine_independent()
    {
        // Roslyn and OSV bake the build agent's absolute path into their SARIF. The same bundle
        // scanned on two machines must unify to the same nodes, or one PR scanned twice looks
        // like two separate problems on two disconnected nodes (B7).
        var windows = WholeToolchain();
        var linux = WholeToolchain();

        foreach (var key in linux.Keys.ToList())
        {
            linux[key] = linux[key]
                .Replace("file:///C:/Users/PC_STORE/Downloads/sentinelai-fixture_2/sentinelai-fixture/",
                         "file:///home/runner/work/sentinelai-fixture/sentinelai-fixture/")
                .Replace("file:///home/runner/work/repo/repo/",
                         "file:///D:/a/repo/repo/");
        }

        var fromWindows = await Build(windows).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);
        var fromLinux = await Build(linux).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        Assert.Equal(
            fromWindows.Select(f => f.NodeRef).OrderBy(x => x, StringComparer.Ordinal),
            fromLinux.Select(f => f.NodeRef).OrderBy(x => x, StringComparer.Ordinal));
    }

    [Fact]
    public async Task Two_tools_reporting_one_package_decorate_one_node()
    {
        // OSV and Trivy both report Newtonsoft.Json 9.0.1. Two findings — two tools saw it —
        // but one node, or the dependency layer splits into per-tool islands (SEC-03).
        var findings = await Normalize();

        var newtonsoft = findings
            .Where(f => f.NodeRef == "pkg:newtonsoft.json:9.0.1")
            .Select(f => f.SourceTool)
            .Distinct()
            .ToList();

        Assert.Contains(ScannerNames.Osv, newtonsoft);
        Assert.Contains(ScannerNames.Trivy, newtonsoft);
    }
}

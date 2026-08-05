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

public class NormalizationPipelineTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private static NormalizationPipeline Build(IBundleStore store, IRuleMappingLookup? ruleMappings = null)
    {
        IFindingExtractor[] extractors =
        [
            new RoslynSarifExtractor(),
            new OsvExtractor(),
            new TrivySarifExtractor(),
            new CheckovSarifExtractor(),
        ];

        var resolver = new RuleMappingResolver(
            ruleMappings ?? new FakeRuleMappingLookup(),
            NullLogger<RuleMappingResolver>.Instance);

        return new NormalizationPipeline(
            extractors, store, resolver, new FindingUnifier(), NullLogger<NormalizationPipeline>.Instance);
    }

    [Fact]
    public async Task Combines_every_tools_findings_and_tags_each_layer()
    {
        var store = new StubBundleStore
        {
            // roslyn: 1 code | osv: 2 dep | trivy: 1 dep + 1 infra | checkov x2: 3 infra
            ["findings/roslyn.sarif"] = Fixtures.RoslynSarifV2,
            ["findings/osv.json"] = Fixtures.OsvNativeJson,
            ["findings/trivy.sarif"] = Fixtures.TrivySarifV2,
            ["findings/checkov_infra.sarif"] = Fixtures.CheckovSarifV1,   // 2 infra
            ["findings/checkov_docker.sarif"] = Fixtures.CheckovDockerSarifV2,   // 1 infra
            // Not a findings file — must not add to the count.
            ["metadata.json"] = "{}",
        };

        var findings = await Build(store).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        Assert.Equal(8, findings.Count);
        Assert.Equal(1, findings.Count(f => f.Layer == Layer.Code));
        Assert.Equal(3, findings.Count(f => f.Layer == Layer.Dep));
        Assert.Equal(4, findings.Count(f => f.Layer == Layer.Infra));

        // Every finding is stamped and ready for the graph stage: the extractors leave NodeRef
        // empty, and the unify step (SEC-16) is what fills it before the stage returns.
        Assert.All(findings, f => Assert.Equal(Job, f.ScanJobId));
        Assert.All(findings, f => Assert.False(string.IsNullOrEmpty(f.SourceTool)));
        Assert.All(findings, f => Assert.True(NodeId.IsCanonical(f.NodeRef), $"not canonical: '{f.NodeRef}'"));
    }

    [Fact]
    public async Task Two_tools_reporting_the_same_package_land_on_one_node()
    {
        // Both fixtures describe Newtonsoft.Json 9.0.1. They stay separate findings — two tools
        // saw it — but they must decorate the same graph node, or the dependency layer splits
        // into per-tool islands and no chain crosses it (SEC-03).
        var store = new StubBundleStore
        {
            ["findings/osv.json"] = Fixtures.OsvNativeJson,
            ["findings/trivy.sarif"] = Fixtures.TrivySarifV2,
        };

        var findings = await Build(store).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        var deps = findings.Where(f => f.Layer == Layer.Dep).ToList();
        Assert.Equal(3, deps.Count);                                  // 2 OSV + 1 Trivy
        Assert.Contains(deps, f => f.SourceTool == ScannerNames.Trivy);
        Assert.All(deps, f => Assert.Equal("pkg:newtonsoft.json:9.0.1", f.NodeRef));
    }

    [Fact]
    public async Task The_same_bundle_scanned_on_two_machines_unifies_identically()
    {
        // The B7 hazard end to end: Roslyn bakes the build agent's absolute path into its
        // SARIF. If that path survives into the dedup key and the node reference, one PR
        // scanned twice produces two findings on two nodes and nothing errors.
        var windows = new StubBundleStore { ["findings/roslyn.sarif"] = Fixtures.RoslynSarifV2 };
        var linux = new StubBundleStore
        {
            ["findings/roslyn.sarif"] = Fixtures.RoslynSarifV2.Replace(
                "file:///C:/Users/PC_STORE/Downloads/sentinelai-fixture_2/sentinelai-fixture/src/",
                "file:///home/runner/work/sentinelai-fixture/sentinelai-fixture/src/"),
        };

        var fromWindows = await Build(windows).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);
        var fromLinux = await Build(linux).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        Assert.Equal(
            Assert.Single(fromWindows).NodeRef,
            Assert.Single(fromLinux).NodeRef);
    }

    [Fact]
    public async Task One_malformed_file_does_not_sink_the_others()
    {
        var store = new StubBundleStore
        {
            ["findings/roslyn.sarif"] = Fixtures.RoslynSarifV2,   // 1 code
            ["findings/trivy.sarif"] = Fixtures.InvalidJson,      // throws, skipped
        };

        var findings = await Build(store).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        var only = Assert.Single(findings);
        Assert.Equal(Layer.Code, only.Layer);
    }

    [Fact]
    public async Task Findings_with_no_cwe_get_one_from_the_rule_mapping_table()
    {
        var store = new StubBundleStore
        {
            // CKV_AWS_20 arrives with CWE-284 already on its rule tags; CKV_DOCKER_2 arrives
            // with nothing, which is exactly the gap rule_mappings exists to close.
            ["findings/checkov_infra.sarif"] = Fixtures.CheckovSarifV1,
            ["findings/checkov_docker.sarif"] = Fixtures.CheckovDockerSarifV2,   // CKV_DOCKER_3, no CWE
            ["findings/trivy.sarif"] = Fixtures.TrivySarifV2,          // AVD-AWS-0089, no CWE
        };

        var ruleMappings = new FakeRuleMappingLookup()
            .With(ScannerNames.Checkov, "CKV_DOCKER_3", "CWE-250")
            .With(ScannerNames.Trivy, "AVD-AWS-0089", "CWE-778");

        var findings = await Build(store, ruleMappings).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        Assert.Equal("CWE-250", Single(findings, ScannerNames.Checkov, "CKV_DOCKER_3").CweId);
        Assert.Equal("CWE-778", Single(findings, ScannerNames.Trivy, "AVD-AWS-0089").CweId);

        // Untouched: the scanner reported this one itself, and nothing maps CKV_DOCKER_2.
        Assert.Equal("CWE-284", Single(findings, ScannerNames.Checkov, "CKV_AWS_20").CweId);
        Assert.Null(Single(findings, ScannerNames.Checkov, "CKV_DOCKER_2").CweId);
    }

    [Fact]
    public async Task An_empty_mapping_table_changes_nothing()
    {
        var store = new StubBundleStore { ["findings/checkov_infra.sarif"] = Fixtures.CheckovSarifV1 };

        var findings = await Build(store).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        Assert.Equal(2, findings.Count);
        Assert.Equal("CWE-284", Single(findings, ScannerNames.Checkov, "CKV_AWS_20").CweId);
        Assert.Null(Single(findings, ScannerNames.Checkov, "CKV_DOCKER_2").CweId);
    }

    private static Finding Single(IReadOnlyList<Finding> findings, string tool, string checkId)
        => Assert.Single(findings.Where(f => f.SourceTool == tool && f.CheckId == checkId));
}

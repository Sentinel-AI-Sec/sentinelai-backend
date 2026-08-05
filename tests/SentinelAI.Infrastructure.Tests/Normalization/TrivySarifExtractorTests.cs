using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Infrastructure.Normalization;

namespace SentinelAI.Infrastructure.Tests.Normalization;

public class TrivySarifExtractorTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private readonly TrivySarifExtractor _extractor = new();

    [Fact]
    public void Tags_a_cve_result_as_dep_and_a_misconfig_result_as_infra()
    {
        var findings = _extractor.Extract(Fixtures.ToStream(Fixtures.TrivySarifV2), Tenant, Job).ToList();

        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(ScannerNames.Trivy, f.SourceTool));

        var vuln = findings.Single(f => f.Layer == Layer.Dep);
        Assert.Equal("CVE-2021-44228", vuln.CveId);
        Assert.Equal("CWE-502", vuln.CweId);
        Assert.Equal(4, vuln.Severity);                 // "error" -> 4

        var misconfig = findings.Single(f => f.Layer == Layer.Infra);
        Assert.Null(misconfig.CveId);
    }

    [Fact]
    public void Malformed_input_throws()
    {
        Assert.Throws<FindingExtractionException>(
            () => _extractor.Extract(Fixtures.ToStream(Fixtures.InvalidJson), Tenant, Job).ToList());
    }
}

using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Infrastructure.Normalization;

namespace SentinelAI.Infrastructure.Tests.Normalization;

public class OsvJsonExtractorTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private readonly OsvJsonExtractor _extractor = new();

    [Fact]
    public void Preserves_the_cve_alias_and_falls_back_to_the_ghsa_id()
    {
        var findings = _extractor.Extract(Fixtures.ToStream(Fixtures.OsvNativeJson), Tenant, Job).ToList();

        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(Layer.Dep, f.Layer));
        Assert.All(findings, f => Assert.Equal(ScannerNames.Osv, f.SourceTool));

        // The reason we read native JSON rather than SARIF: the CVE alias survives.
        var withCve = findings.Single(f => f.CveId == "CVE-2024-21907");
        Assert.Equal("CWE-755", withCve.CweId);
        Assert.Equal(3, withCve.Severity);              // database_specific "HIGH" -> 3

        // No CVE alias -> keep the GHSA id rather than losing the linking key entirely.
        var ghsaOnly = findings.Single(f => f.CveId == "GHSA-aaaa-bbbb-cccc");
        Assert.Equal(2, ghsaOnly.Severity);             // "MODERATE" -> 2
    }

    [Fact]
    public void Malformed_input_throws()
    {
        Assert.Throws<FindingExtractionException>(
            () => _extractor.Extract(Fixtures.ToStream(Fixtures.InvalidJson), Tenant, Job).ToList());
    }
}

using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Infrastructure.Normalization;

namespace SentinelAI.Infrastructure.Tests.Normalization;

public class RoslynSarifExtractorTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private readonly RoslynSarifExtractor _extractor = new();

    [Fact]
    public void Extracts_a_code_finding_with_its_cwe_and_normalized_severity()
    {
        var findings = _extractor.Extract(Fixtures.ToStream(Fixtures.RoslynSarifV2), Tenant, Job).ToList();

        var finding = Assert.Single(findings);
        Assert.Equal(ScannerNames.Roslyn, finding.SourceTool);
        Assert.Equal(Layer.Code, finding.Layer);
        Assert.Equal("CWE-502", finding.CweId);
        Assert.Null(finding.CveId);
        Assert.Equal(3, finding.Severity);              // "warning" -> 3
        Assert.Equal(Tenant, finding.TenantId);
        Assert.Equal(Job, finding.ScanJobId);
        Assert.Equal(string.Empty, finding.NodeRef);    // graph stage fills this in later
        Assert.Contains("deserialization", finding.Message);
    }

    [Fact]
    public void Malformed_input_throws_rather_than_returning_partial_garbage()
    {
        Assert.Throws<FindingExtractionException>(
            () => _extractor.Extract(Fixtures.ToStream(Fixtures.InvalidJson), Tenant, Job).ToList());
    }
}

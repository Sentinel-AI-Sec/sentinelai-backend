using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Infrastructure.Normalization;

namespace SentinelAI.Infrastructure.Tests.Normalization;

public class CheckovSarifExtractorTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private readonly CheckovSarifExtractor _extractor = new();

    // The Checkov sample is SARIF v1 (string message, run.rules, level on the result), so this
    // also pins that the reader tolerates the older shape.
    [Fact]
    public void Extracts_infra_findings_from_sarif_v1()
    {
        var findings = _extractor.Extract(Fixtures.ToStream(Fixtures.CheckovSarifV1), Tenant, Job).ToList();

        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(Layer.Infra, f.Layer));
        Assert.All(findings, f => Assert.Equal(ScannerNames.Checkov, f.SourceTool));

        var withCwe = findings.Single(f => f.CweId is not null);
        Assert.Equal("CWE-284", withCwe.CweId);
        Assert.Equal(4, withCwe.Severity);              // "error" -> 4

        var withoutCwe = findings.Single(f => f.CweId is null);
        Assert.Equal(3, withoutCwe.Severity);           // "warning" -> 3
    }

    [Fact]
    public void Malformed_input_throws()
    {
        Assert.Throws<FindingExtractionException>(
            () => _extractor.Extract(Fixtures.ToStream(Fixtures.InvalidJson), Tenant, Job).ToList());
    }
}

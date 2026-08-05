using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Infrastructure.Normalization;

namespace SentinelAI.Infrastructure.Tests.Normalization;

public class OsvExtractorTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private readonly OsvExtractor _extractor = new();

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

    /// <summary>
    /// The shape the runner actually writes. This is the regression guard for the defect where
    /// <c>scripts/run-scanners.sh</c> emitted <c>osv.sarif</c>, the pipeline accepted only
    /// <c>osv.json</c>, and every OSV finding was discarded with nothing above a debug log.
    /// </summary>
    [Fact]
    public void Reads_the_sarif_shape_the_runner_actually_writes()
    {
        var findings = _extractor.Extract(Fixtures.ToStream(Fixtures.OsvSarifV2), Tenant, Job).ToList();

        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(Layer.Dep, f.Layer));
        Assert.All(findings, f => Assert.Equal(ScannerNames.Osv, f.SourceTool));

        // The linking key survives the SARIF export — the ruleId *is* the advisory id. This is
        // the claim that "OSV's SARIF drops the CVE" got wrong.
        Assert.All(findings, f => Assert.False(string.IsNullOrWhiteSpace(f.CveId)));
        Assert.Contains(findings, f => f.CveId == "CVE-2024-21907");

        // The package, read out of the message, not the lock file the location points at —
        // otherwise every OSV finding decorates one packages.lock.json node (SEC-16).
        Assert.Equal("Newtonsoft.Json@9.0.1", findings.Single(f => f.CveId == "CVE-2024-21907").Location);
        Assert.Equal("SixLabors.ImageSharp@1.0.4", findings.Single(f => f.CveId == "GHSA-2cmq-823j-5qj8").Location);
    }

    [Fact]
    public void Malformed_input_throws()
    {
        Assert.Throws<FindingExtractionException>(
            () => _extractor.Extract(Fixtures.ToStream(Fixtures.InvalidJson), Tenant, Job).ToList());
    }
}

using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Infrastructure.Tests.Normalization;

/// <summary>
/// SEC-16. Two failure modes are worth more than the happy path here, and both are silent:
/// an under-specified dedup key deletes real vulnerabilities, and a missing node reference
/// drops a finding out of the graph without an error.
/// </summary>
public class FindingUnifierTests
{
    private readonly FindingUnifier _unifier = new();

    [Fact]
    public void Collapses_the_same_rule_reported_twice_at_the_same_place()
    {
        var findings = _unifier.Unify(
        [
            Finding(ScannerNames.Trivy, "CVE-2024-0056", Layer.Dep, "src/App/App.deps.json:310", "log4j", cve: "CVE-2024-0056"),
            Finding(ScannerNames.Trivy, "CVE-2024-0056", Layer.Dep, "src/App/App.deps.json:310", "log4j", cve: "CVE-2024-0056"),
        ]);

        Assert.Single(findings);
    }

    [Fact]
    public void Keeps_different_rules_that_fire_on_the_same_line_apart()
    {
        // Checkov reports all three of these on the identical Terraform block. They are three
        // different IAM weaknesses; merging them would delete two real findings.
        var findings = _unifier.Unify(
        [
            Finding(ScannerNames.Checkov, "CKV_AWS_288", Layer.Infra, "infra/iam.tf:25", "Data exfiltration"),
            Finding(ScannerNames.Checkov, "CKV_AWS_289", Layer.Infra, "infra/iam.tf:25", "Permissions management"),
            Finding(ScannerNames.Checkov, "CKV_AWS_290", Layer.Infra, "infra/iam.tf:25", "Unconstrained write"),
        ]);

        Assert.Equal(3, findings.Count);
    }

    [Fact]
    public void Keeps_one_rule_firing_at_different_places_apart()
    {
        var findings = _unifier.Unify(
        [
            Finding(ScannerNames.Checkov, "CKV_AWS_21", Layer.Infra, "infra/main.tf:10", "Versioning disabled"),
            Finding(ScannerNames.Checkov, "CKV_AWS_21", Layer.Infra, "infra/main.tf:88", "Versioning disabled"),
        ]);

        Assert.Equal(2, findings.Count);
    }

    [Fact]
    public void Keeps_two_cves_against_one_package_apart()
    {
        var findings = _unifier.Unify(
        [
            Finding(ScannerNames.Osv, "GHSA-a", Layer.Dep, "Newtonsoft.Json@9.0.1", "advisory", cve: "CVE-2024-21907"),
            Finding(ScannerNames.Osv, "GHSA-b", Layer.Dep, "Newtonsoft.Json@9.0.1", "advisory", cve: "CVE-2024-21908"),
        ]);

        Assert.Equal(2, findings.Count);
    }

    [Fact]
    public void A_collapsed_group_keeps_the_worst_severity()
    {
        var findings = _unifier.Unify(
        [
            Finding(ScannerNames.Trivy, "CVE-1", Layer.Dep, "pkg@1.0", "same", cve: "CVE-1", severity: 1),
            Finding(ScannerNames.Trivy, "CVE-1", Layer.Dep, "pkg@1.0", "same", cve: "CVE-1", severity: 4),
        ]);

        Assert.Equal(4, Assert.Single(findings).Severity);
    }

    [Theory]
    // A code finding decorates the file, not the line — both of these are one node.
    [InlineData(Layer.Code, "src/OrderApp/Controllers/OrdersController.cs:16", "code:src/orderapp/controllers/orderscontroller.cs")]
    [InlineData(Layer.Code, "src/OrderApp/Controllers/OrdersController.cs:204", "code:src/orderapp/controllers/orderscontroller.cs")]
    [InlineData(Layer.Infra, "infra/iam.tf:25", "s3:infra/iam.tf")]
    // A dependency decorates the package; the canonical key separates name and version with
    // ':', and NodeId.TryParse splits on the first one only, so the version survives.
    [InlineData(Layer.Dep, "Newtonsoft.Json@9.0.1", "pkg:newtonsoft.json:9.0.1")]
    public void Builds_the_node_reference_from_the_layer_and_the_location(Layer layer, string location, string expected)
    {
        var finding = Assert.Single(_unifier.Unify([Finding("tool", "R1", layer, location, "m")]));

        Assert.Equal(expected, finding.NodeRef);
        Assert.True(NodeId.IsCanonical(finding.NodeRef));
    }

    [Fact]
    public void A_finding_with_no_location_still_gets_a_canonical_reference()
    {
        var finding = Assert.Single(
            _unifier.Unify([Finding(ScannerNames.Checkov, "CKV_DOCKER_3", Layer.Infra, location: null, "Runs as root")]));

        Assert.True(NodeId.IsCanonical(finding.NodeRef));
        Assert.Contains("ckv_docker_3", finding.NodeRef);
    }

    [Fact]
    public void Every_finding_carries_a_node_reference()
    {
        var findings = _unifier.Unify(
        [
            Finding(ScannerNames.Roslyn, "SCS0028", Layer.Code, "src/A.cs:1", "deserialization"),
            Finding(ScannerNames.Osv, "GHSA-x", Layer.Dep, "Newtonsoft.Json@9.0.1", "advisory"),
            Finding(ScannerNames.Trivy, "AVD-AWS-0089", Layer.Infra, "infra/main.tf:12", "logging off"),
            Finding(ScannerNames.Checkov, "CKV_AWS_21", Layer.Infra, null, "versioning off"),
        ]);

        Assert.Equal(4, findings.Count);
        Assert.All(findings, f => Assert.True(NodeId.IsCanonical(f.NodeRef), $"not canonical: '{f.NodeRef}'"));
    }

    private static Finding Finding(
        string tool, string checkId, Layer layer, string? location, string message,
        string? cve = null, int severity = 3) =>
        new()
        {
            Id = Guid.CreateVersion7(),
            SourceTool = tool,
            CheckId = checkId,
            Layer = layer,
            Location = location,
            Message = message,
            CveId = cve,
            Severity = severity,
        };
}

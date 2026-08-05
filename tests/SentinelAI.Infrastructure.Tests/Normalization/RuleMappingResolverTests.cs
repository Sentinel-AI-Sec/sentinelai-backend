using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Tests.Normalization;

/// <summary>
/// SEC-15. The three rules that define this step: a missing CWE is filled from the exact
/// (tool, check_id) row, a CWE the scanner already reported is never overwritten, and an
/// unmapped rule is left alone rather than guessed at.
/// </summary>
public class RuleMappingResolverTests
{
    private static RuleMappingResolver Build(IRuleMappingLookup lookup)
        => new(lookup, NullLogger<RuleMappingResolver>.Instance);

    private static Finding Finding(string tool, string? checkId, string? cwe = null, Layer layer = Layer.Infra)
        => new()
        {
            Id = Guid.CreateVersion7(),
            SourceTool = tool,
            Layer = layer,
            Severity = 3,
            CweId = cwe,
            CheckId = checkId,
            Message = $"{tool}/{checkId}",
        };

    [Fact]
    public async Task Fills_a_missing_cwe_from_the_exact_check_id()
    {
        // The task's own acceptance example: Checkov reports CKV_AWS_20 with no CWE.
        var lookup = new FakeRuleMappingLookup().With(ScannerNames.Checkov, "CKV_AWS_20", "CWE-284");
        var findings = new List<Finding> { Finding(ScannerNames.Checkov, "CKV_AWS_20") };

        var filled = await Build(lookup).ResolveAsync(findings);

        Assert.Equal(1, filled);
        Assert.Equal("CWE-284", findings[0].CweId);
    }

    [Fact]
    public async Task Leaves_a_finding_that_already_has_a_cwe_untouched()
    {
        // The table disagrees with the scanner on purpose: the scanner's answer must win.
        var lookup = new FakeRuleMappingLookup().With(ScannerNames.Roslyn, "SCS0028", "CWE-284");
        var findings = new List<Finding> { Finding(ScannerNames.Roslyn, "SCS0028", cwe: "CWE-502") };

        var filled = await Build(lookup).ResolveAsync(findings);

        Assert.Equal(0, filled);
        Assert.Equal("CWE-502", findings[0].CweId);
    }

    [Fact]
    public async Task An_unmapped_rule_stays_null_rather_than_being_guessed()
    {
        var lookup = new FakeRuleMappingLookup().With(ScannerNames.Checkov, "CKV_AWS_20", "CWE-284");
        var findings = new List<Finding> { Finding(ScannerNames.Checkov, "CKV_DOCKER_2") };

        var filled = await Build(lookup).ResolveAsync(findings);

        Assert.Equal(0, filled);
        Assert.Null(findings[0].CweId);
    }

    [Fact]
    public async Task The_tool_is_part_of_the_key_so_another_tools_row_never_matches()
    {
        // Same check id string, different scanner: not a match. Rule id namespaces are per-tool.
        var lookup = new FakeRuleMappingLookup().With(ScannerNames.Checkov, "CKV_AWS_20", "CWE-284");
        var findings = new List<Finding> { Finding(ScannerNames.Trivy, "CKV_AWS_20") };

        var filled = await Build(lookup).ResolveAsync(findings);

        Assert.Equal(0, filled);
        Assert.Null(findings[0].CweId);
    }

    [Fact]
    public async Task A_finding_with_no_check_id_is_skipped_and_never_queried()
    {
        var lookup = new FakeRuleMappingLookup().With(ScannerNames.Checkov, "CKV_AWS_20", "CWE-284");
        var findings = new List<Finding> { Finding(ScannerNames.Checkov, checkId: null) };

        var filled = await Build(lookup).ResolveAsync(findings);

        Assert.Equal(0, filled);
        Assert.Null(findings[0].CweId);
        Assert.Equal(0, lookup.BatchCallCount);   // nothing to ask about — no round trip
    }

    [Fact]
    public async Task Repeats_of_one_rule_cost_a_single_lookup_and_all_get_the_cwe()
    {
        var lookup = new FakeRuleMappingLookup().With(ScannerNames.Checkov, "CKV_AWS_20", "CWE-284");
        var findings = new List<Finding>
        {
            Finding(ScannerNames.Checkov, "CKV_AWS_20"),
            Finding(ScannerNames.Checkov, "CKV_AWS_20"),
            Finding(ScannerNames.Checkov, "CKV_AWS_20"),
            Finding(ScannerNames.Roslyn, "SCS0028", cwe: "CWE-502"),   // already linked, not asked about
        };

        var filled = await Build(lookup).ResolveAsync(findings);

        Assert.Equal(3, filled);
        Assert.All(findings.Take(3), f => Assert.Equal("CWE-284", f.CweId));

        Assert.Equal(1, lookup.BatchCallCount);
        Assert.Single(lookup.LastKeys);   // three findings, one distinct rule, one key asked
    }

    [Fact]
    public async Task Case_differences_in_the_check_id_still_resolve()
    {
        // SQL Server's default collation is case-insensitive; the in-memory key must agree,
        // or a row that the database returns would fail to match the finding that asked.
        var lookup = new FakeRuleMappingLookup().With("checkov", "CKV_AWS_20", "CWE-284");
        var findings = new List<Finding> { Finding("Checkov", "ckv_aws_20") };

        var filled = await Build(lookup).ResolveAsync(findings);

        Assert.Equal(1, filled);
        Assert.Equal("CWE-284", findings[0].CweId);
    }

    [Fact]
    public async Task An_empty_list_resolves_nothing_and_asks_nothing()
    {
        var lookup = new FakeRuleMappingLookup();

        Assert.Equal(0, await Build(lookup).ResolveAsync([]));
        Assert.Equal(0, lookup.BatchCallCount);
    }
}

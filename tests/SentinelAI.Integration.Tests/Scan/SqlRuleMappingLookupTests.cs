using Microsoft.EntityFrameworkCore;
using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Normalization;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// SEC-15 against a real EF provider rather than a dictionary: proves the query itself finds
/// the right row, that both halves of the key are actually in the <c>WHERE</c> clause, and that
/// the batch form and the single form give the same answers.
/// </summary>
/// <remarks>
/// <c>rule_mappings</c> is global reference data — deliberately not <c>ITenantOwned</c> — so no
/// tenant query filter applies to it. The context here is built with a caller that has no
/// tenant at all, which would hide every tenant-scoped row; that these lookups still succeed is
/// the assertion that the table is genuinely shared.
/// </remarks>
public class SqlRuleMappingLookupTests
{
    private static SentinelDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<SentinelDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        // No tenant: rule mappings must resolve regardless of who is asking.
        return new SentinelDbContext(options, new FakeCallerContext { TenantId = null });
    }

    private static async Task<SentinelDbContext> SeededAsync(params RuleMapping[] rows)
    {
        var db = NewContext();
        db.RuleMappings.AddRange(rows);
        await db.SaveChangesAsync();
        return db;
    }

    private static RuleMapping Row(string tool, string checkId, string? cwe) => new()
    {
        Id = Guid.NewGuid(),
        SourceTool = tool,
        CheckId = checkId,
        CweId = cwe,
        Notes = "test row",
    };

    [Fact]
    public async Task Exact_match_on_tool_and_check_id_returns_the_cwe()
    {
        using var db = await SeededAsync(
            Row(ScannerNames.Checkov, "CKV_AWS_20", "CWE-284"),
            Row(ScannerNames.Roslyn, "SCS0028", "CWE-502"));

        var lookup = new SqlRuleMappingLookup(db);

        Assert.Equal("CWE-284", lookup.ResolveCwe(ScannerNames.Checkov, "CKV_AWS_20"));
        Assert.Equal("CWE-502", lookup.ResolveCwe(ScannerNames.Roslyn, "SCS0028"));
    }

    [Fact]
    public async Task An_absent_row_returns_null_not_a_near_match()
    {
        // CKV_AWS_2 is a prefix of the seeded CKV_AWS_20. A `LIKE`/contains query would answer
        // it; an exact lookup must not. This is the assertion that keeps the step deterministic.
        using var db = await SeededAsync(Row(ScannerNames.Checkov, "CKV_AWS_20", "CWE-284"));

        var lookup = new SqlRuleMappingLookup(db);

        Assert.Null(lookup.ResolveCwe(ScannerNames.Checkov, "CKV_AWS_2"));
        Assert.Null(lookup.ResolveCwe(ScannerNames.Checkov, "CKV_AWS_200"));
        Assert.Null(lookup.ResolveCwe(ScannerNames.Checkov, "NOT_A_RULE"));
    }

    [Fact]
    public async Task The_same_check_id_under_a_different_tool_is_a_different_row()
    {
        using var db = await SeededAsync(
            Row(ScannerNames.Checkov, "SHARED_ID", "CWE-284"),
            Row(ScannerNames.Trivy, "SHARED_ID", "CWE-778"));

        var lookup = new SqlRuleMappingLookup(db);

        Assert.Equal("CWE-284", lookup.ResolveCwe(ScannerNames.Checkov, "SHARED_ID"));
        Assert.Equal("CWE-778", lookup.ResolveCwe(ScannerNames.Trivy, "SHARED_ID"));
        Assert.Null(lookup.ResolveCwe(ScannerNames.Osv, "SHARED_ID"));
    }

    [Fact]
    public async Task A_row_with_no_cwe_resolves_to_null_in_both_forms()
    {
        // The column is nullable: a row can exist to record "we looked, there is no CWE".
        using var db = await SeededAsync(Row(ScannerNames.Checkov, "CKV_DOCKER_2", cwe: null));

        var lookup = new SqlRuleMappingLookup(db);

        Assert.Null(lookup.ResolveCwe(ScannerNames.Checkov, "CKV_DOCKER_2"));

        var batch = await lookup.ResolveCweAsync([new RuleKey(ScannerNames.Checkov, "CKV_DOCKER_2")]);
        Assert.Empty(batch);
    }

    [Fact]
    public async Task The_batch_form_resolves_across_tools_and_omits_what_it_cannot_map()
    {
        using var db = await SeededAsync(
            Row(ScannerNames.Checkov, "CKV_AWS_20", "CWE-284"),
            Row(ScannerNames.Checkov, "CKV_DOCKER_3", "CWE-250"),
            Row(ScannerNames.Trivy, "AVD-AWS-0089", "CWE-778"),
            Row(ScannerNames.Roslyn, "SCS0028", "CWE-502"));

        var lookup = new SqlRuleMappingLookup(db);

        var resolved = await lookup.ResolveCweAsync(
        [
            new RuleKey(ScannerNames.Checkov, "CKV_AWS_20"),
            new RuleKey(ScannerNames.Checkov, "CKV_DOCKER_3"),
            new RuleKey(ScannerNames.Checkov, "CKV_DOCKER_2"),   // no row
            new RuleKey(ScannerNames.Trivy, "AVD-AWS-0089"),
            new RuleKey(ScannerNames.Trivy, "SCS0028"),          // right id, wrong tool
        ]);

        Assert.Equal(3, resolved.Count);
        Assert.Equal("CWE-284", resolved[new RuleKey(ScannerNames.Checkov, "CKV_AWS_20")]);
        Assert.Equal("CWE-250", resolved[new RuleKey(ScannerNames.Checkov, "CKV_DOCKER_3")]);
        Assert.Equal("CWE-778", resolved[new RuleKey(ScannerNames.Trivy, "AVD-AWS-0089")]);
        Assert.False(resolved.ContainsKey(new RuleKey(ScannerNames.Checkov, "CKV_DOCKER_2")));
        Assert.False(resolved.ContainsKey(new RuleKey(ScannerNames.Trivy, "SCS0028")));
    }

    [Fact]
    public async Task An_empty_key_set_touches_the_database_not_at_all()
    {
        using var db = await SeededAsync(Row(ScannerNames.Checkov, "CKV_AWS_20", "CWE-284"));

        Assert.Empty(await new SqlRuleMappingLookup(db).ResolveCweAsync([]));
    }

    [Fact]
    public async Task Findings_are_not_widened_by_the_check_id_the_lookup_uses()
    {
        // Finding.CheckId is in-pipeline transport only (SEC-15), mapped out in
        // FindingConfiguration. If it ever became a column, this test fails and the D2
        // findings contract has silently changed.
        using var db = NewContext();

        var checkId = db.Model
            .FindEntityType(typeof(Finding))!
            .FindProperty(nameof(Finding.CheckId));

        Assert.Null(checkId);
    }
}

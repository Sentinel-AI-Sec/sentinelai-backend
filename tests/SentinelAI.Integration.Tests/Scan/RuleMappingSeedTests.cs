using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Implementation.Repositories;
using SentinelAI.Infrastructure.Normalization;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// Pins the <c>rule_mappings</c> seed against the rule ids the scanners actually emit (SEC-15).
/// </summary>
/// <remarks>
/// <para>
/// This test exists because the previous seed passed every test it had and still resolved
/// almost nothing. It was written from the scanners' published rule catalogues, and its unit
/// tests were written from the same assumption — <c>AVD-AWS-0089</c> was asserted by a
/// hand-written SARIF sample that spelled it exactly as the seed did. The test and the code
/// agreed with each other and neither agreed with Trivy, which emits <c>AWS-0089</c>.
/// </para>
/// <para>
/// So the assertions below deliberately do <em>not</em> use hand-written fixtures. They use the
/// rule ids parsed out of the committed <c>sentinelai-fixtures/scan_out/</c> SARIF, hard-coded
/// here so the test is hermetic, with the counts stated so a drifting fixture is visible.
/// A mapping table is reference data whose only job is to match real output; a test that does
/// not compare it to real output cannot tell whether it works.
/// </para>
/// </remarks>
public class RuleMappingSeedTests
{
    /// <summary>
    /// Every rule id in <c>scan_out/roslyn.sarif</c> — 5 results, 4 distinct.
    /// Not one of them carries a CWE tag, which is why this table is the only linking path.
    /// </summary>
    private static readonly string[] RoslynRules = ["SCS0028", "SCS0006", "SCS0007", "SCS0002"];

    /// <summary>
    /// Every rule id in <c>scan_out/checkov-infra.sarif</c> (28 results, 19 distinct) and
    /// <c>checkov-docker.sarif</c> (3 results, 3 distinct). None carries a CWE tag.
    /// </summary>
    private static readonly string[] CheckovRules =
    [
        "CKV_AWS_290", "CKV_AWS_289", "CKV_AWS_288", "CKV_AWS_355", "CKV_AWS_23",
        "CKV_AWS_249", "CKV_AWS_336", "CKV_AWS_333", "CKV_AWS_53", "CKV_AWS_54",
        "CKV_AWS_55", "CKV_AWS_56", "CKV2_AWS_62", "CKV_AWS_18", "CKV_AWS_144",
        "CKV2_AWS_61", "CKV_AWS_145", "CKV2_AWS_6", "CKV_AWS_21",
        "CKV_DOCKER_3", "CKV_DOCKER_2", "CKV_SECRET_6",
    ];

    /// <summary>
    /// The misconfiguration rule ids in <c>scan_out/trivy.sarif</c>. Trivy's vulnerability
    /// results are keyed by CVE and need no mapping — they arrive with a linking key.
    /// <b>Note the absent <c>AVD-</c> prefix.</b>
    /// </summary>
    private static readonly string[] TrivyMisconfigRules =
    [
        "AWS-0086", "AWS-0087", "AWS-0089", "AWS-0090", "AWS-0091", "AWS-0093",
        "AWS-0094", "AWS-0104", "AWS-0124", "AWS-0132", "AWS-0345",
        "DS-0002", "DS-0026", "DS-0031",
    ];

    private static SentinelDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<SentinelDbContext>()
            .UseInMemoryDatabase($"seed-{Guid.NewGuid()}")
            .Options;

        var db = new SentinelDbContext(options, new FakeCallerContext());
        db.Database.EnsureCreated();
        return db;
    }

    [Theory]
    [InlineData(ScannerNames.Roslyn)]
    [InlineData(ScannerNames.Checkov)]
    [InlineData(ScannerNames.Trivy)]
    public void Every_rule_the_fixture_emits_resolves_to_a_cwe(string tool)
    {
        using var db = NewContext();
        var lookup = new SqlRuleMappingLookup(db);

        var rules = tool switch
        {
            ScannerNames.Roslyn => RoslynRules,
            ScannerNames.Checkov => CheckovRules,
            _ => TrivyMisconfigRules,
        };

        var unmapped = rules.Where(id => lookup.ResolveCwe(tool, id) is null).ToArray();

        Assert.True(
            unmapped.Length == 0,
            $"{tool}: {unmapped.Length} rule(s) the fixture emits have no mapping — " +
            $"they reach the corpus with no linking key: {string.Join(", ", unmapped)}");
    }

    /// <summary>
    /// Every seeded check id is spelled the way its tool spells rule ids.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the inverse guard, and it is deliberately about <em>grammar</em> rather than
    /// about the fixture. Rows for rules this particular fixture does not happen to trigger are
    /// legitimate and wanted — the fixture is one repository and the table serves all of them.
    /// A row whose id could never match <em>any</em> output of that scanner is not.
    /// </para>
    /// <para>
    /// That is exactly how the two Trivy rows failed: <c>AVD-AWS-0089</c> is how Trivy's
    /// documentation writes the rule and is not a string Trivy ever emits, so the row was
    /// unmatchable rather than merely unused. A prefix check catches that class; comparing
    /// against the fixture would also have banned the useful forward-looking rows.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(ScannerNames.Roslyn, "SCS")]
    [InlineData(ScannerNames.Checkov, "CKV")]
    public void Seeded_ids_use_their_tools_own_spelling(string tool, string expectedPrefix)
    {
        using var db = NewContext();

        var wrong = db.RuleMappings.AsNoTracking()
            .Where(r => r.SourceTool == tool)
            .ToList()
            .Where(r => !r.CheckId.StartsWith(expectedPrefix, StringComparison.Ordinal))
            .Select(r => r.CheckId)
            .ToArray();

        Assert.True(wrong.Length == 0, $"{tool} ids must start with '{expectedPrefix}': {string.Join(", ", wrong)}");
    }

    [Fact]
    public void No_trivy_row_carries_the_documentation_only_AVD_prefix()
    {
        using var db = NewContext();

        var prefixed = db.RuleMappings.AsNoTracking()
            .Where(r => r.SourceTool == ScannerNames.Trivy)
            .ToList()
            .Where(r => r.CheckId.StartsWith("AVD-", StringComparison.OrdinalIgnoreCase))
            .Select(r => r.CheckId)
            .ToArray();

        Assert.True(
            prefixed.Length == 0,
            $"Trivy emits AWS-00xx, never AVD-AWS-00xx — these rows can never match: {string.Join(", ", prefixed)}");
    }

    /// <summary>Every row must resolve to something; a null CWE is dead weight in this table.</summary>
    [Fact]
    public void Every_seeded_row_carries_a_cwe()
    {
        using var db = NewContext();
        Assert.All(db.RuleMappings.AsNoTracking().ToList(), r => Assert.False(string.IsNullOrWhiteSpace(r.CweId)));
    }

    /// <summary>
    /// The flagship path, asserted by name: SCS0028 is the fixture's unsafe-deserialization
    /// sink and it reports no CWE of its own, so this row is the whole link between the demo's
    /// headline finding and the knowledge corpus.
    /// </summary>
    [Fact]
    public void The_flagship_deserialization_finding_reaches_CWE_502()
    {
        using var db = NewContext();
        Assert.Equal("CWE-502", new SqlRuleMappingLookup(db).ResolveCwe(ScannerNames.Roslyn, "SCS0028"));
    }

    /// <summary>
    /// SCS0026 is LDAP injection and SCS0002 is SQL injection. Mapping SCS0026 to CWE-89 does
    /// not fail — it attaches SQL-injection knowledge to an LDAP-injection finding and reports
    /// it confidently, which is worse than resolving nothing.
    /// </summary>
    [Fact]
    public void The_injection_rules_map_to_their_own_cwes()
    {
        using var db = NewContext();
        var lookup = new SqlRuleMappingLookup(db);

        Assert.Equal("CWE-89", lookup.ResolveCwe(ScannerNames.Roslyn, "SCS0002"));   // SQL
        Assert.Equal("CWE-90", lookup.ResolveCwe(ScannerNames.Roslyn, "SCS0026"));   // LDAP
    }

    /// <summary>
    /// Trivy emits its misconfiguration ids without the <c>AVD-</c> prefix its documentation
    /// uses. Seeding the prefixed form produces rows that never match.
    /// </summary>
    [Fact]
    public void Trivy_rows_are_keyed_without_the_AVD_prefix()
    {
        using var db = NewContext();
        var lookup = new SqlRuleMappingLookup(db);

        Assert.NotNull(lookup.ResolveCwe(ScannerNames.Trivy, "AWS-0089"));
        Assert.Null(lookup.ResolveCwe(ScannerNames.Trivy, "AVD-AWS-0089"));
    }
}

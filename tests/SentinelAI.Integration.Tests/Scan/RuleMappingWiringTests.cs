using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// SEC-15 through the <em>real</em> DI container and the <em>real</em> seeded table.
/// </summary>
/// <remarks>
/// The unit tests prove the resolver's behaviour against a fake, and
/// <c>SqlRuleMappingLookupTests</c> proves the query against a real provider — but both would
/// still pass if <c>AddInfrastructureServices</c> never registered <c>IRuleMappingLookup</c>,
/// or if the seed rows were dropped from the migration. Those two failures are invisible until
/// a scan runs in production and quietly resolves nothing. This boots the app the way
/// <c>Program.cs</c> does and asks the container for the real thing.
/// </remarks>
public class RuleMappingWiringTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;

    public RuleMappingWiringTests(ScanApiFactory factory) => _factory = factory;

    /// <summary>
    /// A scope over the app's own container, with the seeded reference data applied.
    /// <c>EnsureCreated</c> is what materializes <c>HasData</c> rows on the in-memory provider,
    /// the same rows the SQL migration inserts.
    /// </summary>
    private IServiceScope SeededScope()
    {
        var scope = _factory.Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<SentinelDbContext>().Database.EnsureCreated();
        return scope;
    }

    [Fact]
    public void The_container_resolves_the_sql_lookup_and_the_resolver()
    {
        using var scope = SeededScope();

        // GetRequiredService, not GetService: a missing registration must fail loudly here
        // rather than silently disable CWE resolution at runtime.
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IRuleMappingLookup>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<RuleMappingResolver>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<NormalizationPipeline>());
    }

    [Fact]
    public void The_seeded_mappings_survive_into_a_created_database()
    {
        using var scope = SeededScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();

        var mappings = db.RuleMappings.AsNoTracking().ToList();

        Assert.Equal(13, mappings.Count);
        Assert.Contains(mappings, m => m is { SourceTool: "checkov", CheckId: "CKV_AWS_20", CweId: "CWE-284" });
        Assert.Contains(mappings, m => m is { SourceTool: "trivy", CheckId: "AVD-AWS-0089", CweId: "CWE-778" });
        Assert.Contains(mappings, m => m is { SourceTool: "roslyn", CheckId: "SCS0028", CweId: "CWE-502" });

        // Every seeded row must actually resolve to something, or it is dead weight in a table
        // whose only job is resolving.
        Assert.All(mappings, m => Assert.False(string.IsNullOrWhiteSpace(m.CweId)));

        // The unique key holds across the seed set — a duplicate would make resolution
        // nondeterministic, and the in-memory provider does not enforce the index for us.
        Assert.Equal(
            mappings.Count,
            mappings.Select(m => new RuleKey(m.SourceTool, m.CheckId)).Distinct().Count());
    }

    [Fact]
    public async Task A_real_checkov_finding_with_no_cwe_is_resolved_by_the_wired_pipeline()
    {
        using var scope = SeededScope();
        var resolver = scope.ServiceProvider.GetRequiredService<RuleMappingResolver>();

        var findings = new List<Finding>
        {
            Unlinked(ScannerNames.Checkov, "CKV_AWS_20"),     // seeded  → CWE-284
            Unlinked(ScannerNames.Trivy, "AVD-AWS-0089"),     // seeded  → CWE-778
            Unlinked(ScannerNames.Checkov, "CKV_DOCKER_2"),   // no row  → stays null
            new()
            {
                Id = Guid.CreateVersion7(),
                SourceTool = ScannerNames.Roslyn,
                Layer = Layer.Code,
                Severity = 4,
                CweId = "CWE-502",                            // scanner already linked it
                CheckId = "SCS0028",
                Message = "Unsafe deserialization.",
            },
        };

        var filled = await resolver.ResolveAsync(findings);

        Assert.Equal(2, filled);
        Assert.Equal("CWE-284", findings[0].CweId);
        Assert.Equal("CWE-778", findings[1].CweId);
        Assert.Null(findings[2].CweId);
        Assert.Equal("CWE-502", findings[3].CweId);
    }

    private static Finding Unlinked(string tool, string checkId) => new()
    {
        Id = Guid.CreateVersion7(),
        SourceTool = tool,
        Layer = Layer.Infra,
        Severity = 3,
        CweId = null,
        CheckId = checkId,
        Message = $"{tool} reported {checkId} with no CWE.",
    };
}

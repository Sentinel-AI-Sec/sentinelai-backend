using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Debate;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Application.Features.Scan.Reporting;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Application.Features.Scan.ThinSlice;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Implementation.Repositories;
using SentinelAI.Infrastructure.Knowledge;
using SentinelAI.Infrastructure.Normalization;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// SEC-45 with nothing stubbed out that the project actually owns: the <em>real</em> debate
/// engine, the real normalization stage, the real rule-mapping table.
/// </summary>
/// <remarks>
/// <para>
/// <c>WalkingSkeletonTests</c> asserts each seam in isolation with a scripted debate, which is
/// the right tool for pinning a boundary shape. This file answers the different question the
/// acceptance box actually asks — does the pipe <em>run</em> — by putting the real
/// <see cref="DebateEngine"/> in the middle of it, over the scripted model provider so it stays
/// offline and deterministic.
/// </para>
/// <para>
/// The only stub left is <see cref="SeedKnowledgeRetriever"/>, because the corpus it would read
/// does not exist yet (SEC-09). That is the one seam still standing on a placeholder, and it is
/// named here rather than hidden.
/// </para>
/// </remarks>
public class WalkingSkeletonEndToEndTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    /// <summary>The real engine, wired to the scripted provider — no network, no credentials.</summary>
    private static DebateEngine RealDebateOffline()
    {
        var providerOptions = new ModelProviderOptions { Provider = ModelProvider.Scripted };
        return new DebateEngine(
            new ChatClientFactory(providerOptions),
            Options.Create(new DebateOptions { MaxRounds = 2 }));
    }

    private static ThinSlicePipeline Build() =>
        new(new GraphSeeder(),
            new RetrievalQueryBuilder(),
            new SeedKnowledgeRetriever(NullLogger<SeedKnowledgeRetriever>.Instance),
            new ScanBriefRenderer(),
            RealDebateOffline(),
            new ReportBuilder(),
            NullLogger<ThinSlicePipeline>.Instance);

    private static Finding SeededFinding() => new()
    {
        Id = Guid.CreateVersion7(),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = ScannerNames.Roslyn,
        CheckId = "SCS0028",
        Layer = Layer.Code,
        Severity = 4,
        CweId = "CWE-502",
        NodeRef = NodeId.Code("OrderService"),
        Message = "Unsafe deserialization in OrderService",
    };

    [Fact]
    public async Task The_seeded_finding_walks_the_whole_pipe_through_the_real_debate_engine()
    {
        var result = await Build().RunAsync([SeededFinding()], Tenant, Job);

        // Normalize -> graph -> retrieve
        Assert.Equal("code:orderservice", Assert.Single(result.Nodes).NodeKey);
        Assert.NotEmpty(result.Knowledge);

        // Debate — the real engine ran and terminated. Which way it ended is not this test's
        // business; that it always ends is SEC-02's hard criterion and it must hold here too.
        Assert.NotEmpty(result.Audit.Transcript);
        Assert.InRange(result.Audit.Rounds, 1, 2);
        Assert.True(
            Enum.IsDefined(result.Audit.Outcome),
            "the debate must report an outcome, not an unset enum");

        // Report
        Assert.Equal(ReportBuilder.DraftAudit, result.Report.Framing);
        Assert.Contains("not a verified verdict", result.Report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(result.Report.Citations);
    }

    [Fact]
    public async Task The_debate_always_terminates_even_when_the_brief_is_empty()
    {
        // An empty graph is a real case — a clean PR produces one — and the pipe must return a
        // report rather than hanging or throwing.
        var result = await Build().RunAsync([], Tenant, Job);

        Assert.Empty(result.Nodes);
        Assert.Empty(result.Knowledge);
        Assert.Empty(result.Report.Citations);
        Assert.NotNull(result.Report);
        Assert.Equal(ReportBuilder.DraftAudit, result.Report.Framing);
    }

    /// <summary>
    /// The whole backend, from the bytes a runner uploads to a persistable report: the real
    /// normalization stage (SEC-14/15/16) feeding the real thin slice (SEC-45).
    /// </summary>
    /// <remarks>
    /// This is the end-of-sprint proof the sprint document asks for, minus the HTTP hop. It uses
    /// the filenames <c>scripts/run-scanners.sh</c> writes, because that string has been where
    /// the defects live.
    /// </remarks>
    [Fact]
    public async Task A_whole_bundle_walks_the_pipe_from_scanner_output_to_a_cited_report()
    {
        var options = new DbContextOptionsBuilder<SentinelDbContext>()
            .UseInMemoryDatabase($"skeleton-{Guid.NewGuid()}").Options;
        using var db = new SentinelDbContext(options, new FakeCallerContext());
        db.Database.EnsureCreated();

        var store = new InMemoryBundle
        {
            ["findings/roslyn.sarif"] = BundleSamples.Roslyn,
            ["findings/osv.sarif"] = BundleSamples.Osv,
            ["findings/checkov_infra.sarif"] = BundleSamples.Checkov,
        };

        IFindingExtractor[] extractors =
        [
            new RoslynSarifExtractor(), new OsvExtractor(),
            new TrivySarifExtractor(), new CheckovSarifExtractor(),
        ];

        var normalization = new NormalizationPipeline(
            extractors,
            store,
            new RuleMappingResolver(new SqlRuleMappingLookup(db), NullLogger<RuleMappingResolver>.Instance),
            new FindingUnifier(),
            NullLogger<NormalizationPipeline>.Instance);

        // Stage 1, for real.
        var findings = await normalization.NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        Assert.NotEmpty(findings);
        Assert.Contains(findings, f => f.SourceTool == ScannerNames.Roslyn);
        Assert.Contains(findings, f => f.SourceTool == ScannerNames.Osv);
        Assert.Contains(findings, f => f.SourceTool == ScannerNames.Checkov);

        // Stages 2-5, for real.
        var result = await Build().RunAsync(findings, Tenant, Job);

        // The seam that carries the whole thing: every finding joins a node by exact key.
        var nodeKeys = result.Nodes.Select(n => n.NodeKey).ToHashSet(StringComparer.Ordinal);
        Assert.All(result.Findings, f => Assert.Contains(f.NodeRef, nodeKeys));

        // All three layers survived to the graph, so a cross-layer chain is expressible.
        Assert.Contains(result.Nodes, n => n.Layer == Layer.Code);
        Assert.Contains(result.Nodes, n => n.Layer == Layer.Dep);
        Assert.Contains(result.Nodes, n => n.Layer == Layer.Infra);

        // The flagship finding kept its CWE through the rule-mapping table and reached the
        // corpus — the path SEC-15 exists to create.
        Assert.Contains(findings, f => f.CheckId == "SCS0028" && f.CweId == "CWE-502");
        Assert.Contains(result.Report.Citations, c => c.KnowledgeId == "CWE-502");

        Assert.Equal(ReportBuilder.DraftAudit, result.Report.Framing);
        Assert.Equal(Job, result.Report.ScanJobId);
    }

    private sealed class InMemoryBundle : Dictionary<string, string>, IBundleStore
    {
        public Task<IReadOnlyList<StoredBundleFile>> OpenFindingsAsync(string locator, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<StoredBundleFile>>(
                this.Select(kv => new StoredBundleFile(kv.Key, System.Text.Encoding.UTF8.GetBytes(kv.Value))).ToList());

        public Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct)
            => throw new NotSupportedException();

        public Task<IReadOnlyList<StoredBundleFile>> OpenGraphInputsAsync(string locator, CancellationToken ct)
            => throw new NotSupportedException();

        public Task PurgeAsync(Guid scanJobId, CancellationToken ct) => throw new NotSupportedException();
    }

    /// <summary>
    /// Trimmed slices of the committed fixture's real scanner output — same rule ids, same
    /// message wording, same absolute-path shape Roslyn and OSV emit.
    /// </summary>
    private static class BundleSamples
    {
        public const string Roslyn = """
        {
          "version": "2.1.0",
          "runs": [{
            "tool": { "driver": { "name": "SecurityCodeScan", "rules": [{ "id": "SCS0028" }] } },
            "results": [{
              "ruleId": "SCS0028", "level": "warning",
              "message": { "text": "TypeNameHandling is set to the other value than 'None'. It may lead to deserialization vulnerability." },
              "locations": [{ "physicalLocation": {
                "artifactLocation": { "uri": "file:///C:/Users/PC_STORE/Downloads/fixture/src/OrderApp/Controllers/OrdersController.cs" },
                "region": { "startLine": 16 } } }]
            }]
          }]
        }
        """;

        public const string Osv = """
        {
          "version": "2.1.0",
          "runs": [{
            "tool": { "driver": { "name": "osv-scanner", "rules": [{ "id": "CVE-2024-21907" }] } },
            "results": [{
              "ruleId": "CVE-2024-21907", "level": "warning",
              "message": { "text": "Package 'Newtonsoft.Json@12.0.1' is vulnerable to 'CVE-2024-21907'." },
              "locations": [{ "physicalLocation": {
                "artifactLocation": { "uri": "file:///C:/Users/PC_STORE/Downloads/fixture/src/OrderApp/packages.lock.json" } } }]
            }]
          }]
        }
        """;

        public const string Checkov = """
        {
          "version": "2.1.0",
          "runs": [{
            "tool": { "driver": { "name": "Checkov", "rules": [{ "id": "CKV_AWS_290" }] } },
            "results": [{
              "ruleId": "CKV_AWS_290", "level": "error",
              "message": { "text": "Ensure IAM policies does not allow write access without constraints" },
              "locations": [{ "physicalLocation": {
                "artifactLocation": { "uri": "infra/iam.tf" }, "region": { "startLine": 25 } } }]
            }]
          }]
        }
        """;
    }
}

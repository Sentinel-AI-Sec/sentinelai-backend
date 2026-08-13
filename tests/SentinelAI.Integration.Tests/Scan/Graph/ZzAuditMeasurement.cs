using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Graph;
using SentinelAI.Infrastructure.Normalization;
using Xunit.Abstractions;

namespace SentinelAI.Integration.Tests.Scan.Graph;

/// <summary>
/// TEMPORARY audit instrumentation — not a test. Runs the shipped stages over the REAL
/// committed fixture files and prints what attaches. Delete after the audit.
/// </summary>
public class ZzAuditMeasurement(ITestOutputHelper output)
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();
    private const string Locator = "fake://fixture";

    private static string FixtureRoot =>
        @"E:\ITI\Graduation Project\workspace\sentinelai-fixtures";

    private static Dictionary<string, string> RealHcl()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in Directory.GetFiles(Path.Combine(FixtureRoot, "infra"), "*.tf"))
            map[$"graph-inputs/infra/{Path.GetFileName(f)}"] = File.ReadAllText(f);
        return map;
    }

    [Fact]
    public async Task Measure()
    {
        var hcl = RealHcl();
        var dockerfile = File.ReadAllText(Path.Combine(FixtureRoot, "Dockerfile"));
        var lockFile = File.ReadAllText(Path.Combine(FixtureRoot, "src", "OrderApp", "packages.lock.json"));

        output.WriteLine($"Dockerfile has LABEL org.sentinelai.image : {dockerfile.Contains("org.sentinelai.image")}");
        output.WriteLine($"hcl files: {string.Join(", ", hcl.Keys)}");

        // ---- build the graph from the real seam readers -------------------------------
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var store = new FakeGraphInputsStore { Files = hcl };

        await new InfraSpineWriter(store,
                new TerraformInfraSpineReader(NullLogger<TerraformInfraSpineReader>.Instance),
                unitOfWork, NullLogger<InfraSpineWriter>.Instance)
            .WriteAsync(Locator, Tenant, Job, CancellationToken.None);

        await new DepCodeSeamWriter(new DepCodeSeamReader(NullLogger<DepCodeSeamReader>.Instance),
                unitOfWork, NullLogger<DepCodeSeamWriter>.Instance)
            .WriteAsync("src/OrderApp/packages.lock.json", lockFile, Tenant, Job, CancellationToken.None);

        await new CodeInfraSeamWriter(new CodeInfraSeamReader(), unitOfWork,
                NullLogger<CodeInfraSeamWriter>.Instance)
            .WriteAsync("Dockerfile", dockerfile, hcl, Tenant, Job, CancellationToken.None);

        await new RoleResourceSeamWriter(new RoleResourceSeamReader(), unitOfWork,
                NullLogger<RoleResourceSeamWriter>.Instance)
            .WriteAsync(hcl, Tenant, Job, CancellationToken.None);

        var nodes = unitOfWork.FakeRepository<GraphNode>().Added;
        var edges = unitOfWork.FakeRepository<GraphEdge>().Added;
        output.WriteLine($"\nNODES {nodes.Count}: {string.Join(", ", nodes.Select(n => n.NodeKey).Order())}");
        output.WriteLine($"EDGES {edges.Count}");
        foreach (var e in edges)
        {
            var f = nodes.FirstOrDefault(n => n.Id == e.FromNodeId)?.NodeKey;
            var t = nodes.FirstOrDefault(n => n.Id == e.ToNodeId)?.NodeKey;
            output.WriteLine($"   {f} --{e.Relation}--> {t}  ({e.Confidence})");
        }

        // ---- real findings from the committed SARIF -----------------------------------
        var findings = await RealFindingsAsync();
        output.WriteLine($"\nFINDINGS {findings.Count}");
        foreach (var g in findings.GroupBy(f => f.Layer))
            output.WriteLine($"   {g.Key}: {g.Count()}");

        // ---- decorate ------------------------------------------------------------------
        var locator = new TerraformFindingLocator(NullLogger<TerraformFindingLocator>.Instance);
        var map = await locator.LocateAsync(Locator, CancellationToken.None) is { } m ? m : null;
        output.WriteLine($"\nLocator map entries: {map?.Count ?? -1}");

        var decorated = new GraphDecorator(NullLogger<GraphDecorator>.Instance)
            .Decorate(nodes, findings, map);

        output.WriteLine($"\nATTACHED nodes: {decorated.FindingsByNodeKey.Count}");
        foreach (var kv in decorated.FindingsByNodeKey.OrderBy(k => k.Key))
            output.WriteLine($"   {kv.Key}: {kv.Value.Count} finding(s)");
        output.WriteLine($"UNATTACHED findings: {decorated.Unattached.Count} of {findings.Count}");
        foreach (var g in decorated.Unattached.GroupBy(f => f.Layer))
            output.WriteLine($"   unattached {g.Key}: {g.Count()}");

        var attachedCount = findings.Count - decorated.Unattached.Count;
        output.WriteLine($"\n>>> ATTACHED {attachedCount} of {findings.Count} findings");
        output.WriteLine($">>> HOT nodes: {nodes.Count(n => n.IsHot)}");

        // ---- traverse -------------------------------------------------------------------
        var chains = new ExploitChainTraverser(NullLogger<ExploitChainTraverser>.Instance)
            .Traverse(nodes, edges, decorated);
        output.WriteLine($"\n>>> CANDIDATE CHAINS: {chains.Count}");
        foreach (var c in chains)
            output.WriteLine($"   {string.Join(" -> ", c.Hops.Select(h => h.Node.NodeKey))}  min={c.MinConfidence}");
    }

    private static async Task<IReadOnlyList<Finding>> RealFindingsAsync()
    {
        var scanOut = Path.Combine(FixtureRoot, "scan_out");
        var raw = new List<Finding>();

        var extractors = new (string File, string Tool)[]
        {
            ("roslyn.sarif", "roslyn"),
            ("osv.sarif", "osv"),
            ("trivy.sarif", "trivy"),
            ("checkov-infra.sarif", "checkov"),
            ("checkov-docker.sarif", "checkov"),
        };

        foreach (var (file, tool) in extractors)
        {
            var path = Path.Combine(scanOut, file);
            if (!File.Exists(path)) continue;
            await using var stream = File.OpenRead(path);
            var extractor = ExtractorFor(tool, file);
            raw.AddRange(extractor.Extract(stream, Tenant, Job));
        }

        return new FindingUnifier().Unify(raw);
    }

    private static SentinelAI.Domain.Abstractions.IFindingExtractor ExtractorFor(string tool, string file) =>
        file.StartsWith("osv") ? new OsvJsonExtractor()
        : file.StartsWith("roslyn") ? new RoslynSarifExtractor()
        : file.StartsWith("trivy") ? new TrivySarifExtractor()
        : new CheckovSarifExtractor();
}

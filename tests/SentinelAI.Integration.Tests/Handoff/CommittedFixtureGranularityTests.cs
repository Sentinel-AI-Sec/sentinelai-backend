using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Graph;
using SentinelAI.Infrastructure.Normalization;
using SentinelAI.Integration.Tests.Scan;
using SentinelAI.Integration.Tests.Scan.Graph;
using Xunit.Abstractions;

namespace SentinelAI.Integration.Tests.Handoff;

/// <summary>
/// SEC-47's second acceptance box, measured against the committed fixture on disk: the findings
/// the scanners produced and the graph the seam readers build out of the same repository join,
/// rather than sitting beside each other as two sets of islands.
/// </summary>
/// <remarks>
/// <para>
/// <b>What the existing mismatch test does not cover.</b>
/// <see cref="CanonicalIdMismatchTests"/> feeds the seam a <em>syntactically</em> wrong key
/// (<c>role:order</c>) and proves <see cref="GraphSeeder"/> throws. That guard is worth having,
/// but it is not the bug the ticket was written for. The bug was two perfectly canonical keys at
/// different granularities:
/// </para>
/// <code>
/// finding:  pkg:newtonsoft.json:12.0.1   canonical, parses, nothing throws
/// node:     pkg:newtonsoft.json          canonical, parses, nothing throws
/// </code>
/// <para>
/// Both pass <see cref="NodeId.IsCanonical"/>, so no guard fires, no exception is raised, and the
/// graph splits silently. The only thing that catches that is measuring whether the two sides
/// actually meet — which is what this file does.
/// </para>
/// <para>
/// <b>Why it reads from disk.</b> Not one other test in this solution does. Every fixture input
/// elsewhere is a <c>const</c> someone pasted and then edited independently of the fixture, which
/// is exactly how <see cref="Scan.Graph.FlagshipChainTests"/> spent a sprint asserting the
/// flagship chain over a Dockerfile whose <c>LABEL org.sentinelai.image</c> line the real fixture
/// did not have: green test, broken product. A constant cannot catch fixture drift, because a
/// constant is the drift. See <see cref="FixtureRepo"/> for the skip behaviour when the sibling
/// repository is not checked out.
/// </para>
/// <para>
/// <b>Floors, not exact numbers.</b> The attach counts are asserted as bounds. The fixture is
/// edited by hand and a new <c>VULN</c> block or a re-run scanner legitimately moves the totals by
/// a few; pinning an exact number would make this file fail for reasons that say nothing about
/// the product. A granularity regression does not move the count by a few — it collapses a whole
/// layer to zero — and the bounds here are wide enough to ignore the first and narrow enough to
/// catch the second.
/// </para>
/// <para>
/// <b>Verified by breaking it.</b> Not claimed — measured. Removing the version-stripping step
/// from <c>GraphDecorator</c>'s package rule (rule 2, the literal shape of finding 18-A) took the
/// dependency layer from 28/28 to 0/28 and failed four of the six tests here, reporting
/// <c>pkg:newtonsoft.json:12.0.1</c> against <c>pkg:newtonsoft.json</c> side by side. The change
/// was reverted; the point of recording it is that the assertions are known to bite rather than
/// assumed to.
/// </para>
/// </remarks>
public class CommittedFixtureGranularityTests(ITestOutputHelper output)
{
    /// <summary>
    /// Measured against the committed fixture on 2026-08-14: 76 of 85 unified findings attach —
    /// Code 5/5, Dep 28/28, Infra 43/52. The nine that do not are the six located on the root
    /// <c>Dockerfile</c> (three from Checkov, three from Trivy — no <c>NodeType</c> models a
    /// container build file) and three <c>infra/main.tf</c> lines that fall inside no block with a
    /// canonical node type. Both are honest gaps, not regressions, so they are bounded rather than
    /// driven to zero.
    /// </summary>
    private const int AttachedFloor = 70;
    private const int UnattachedCeiling = 12;

    /// <summary>
    /// The whole point of the exercise: every layer that was scanned reaches the graph.
    /// </summary>
    /// <remarks>
    /// One assertion per layer rather than one over the total, because a total can stay healthy
    /// while a layer dies — the dependency layer collapsing to zero while Trivy's 30-odd infra
    /// findings carry the count is precisely the shape of finding 18-A, and a single
    /// "attached &gt;= 70" would have sailed straight past it.
    /// </remarks>
    [CommittedFixtureFact]
    public async Task Every_scanned_layer_joins_the_graph_built_from_the_same_repository()
    {
        var fixture = await CommittedFixture.BuildAsync();
        output.WriteLine(fixture.Report());

        foreach (var layer in new[] { Layer.Dep, Layer.Code, Layer.Infra })
            AssertLayerAttaches(fixture, layer);
    }

    /// <summary>
    /// The bounded totals, so a regression that halves the attach rate without emptying any one
    /// layer still fails.
    /// </summary>
    [CommittedFixtureFact]
    public async Task Most_of_the_committed_fixtures_findings_attach_to_a_graph_node()
    {
        var fixture = await CommittedFixture.BuildAsync();
        output.WriteLine(fixture.Report());

        var attached = fixture.AttachedFindings.Count;

        Assert.True(
            attached >= AttachedFloor,
            $"Only {attached} of {fixture.Findings.Count} committed-fixture findings attached to a "
            + $"graph node (floor {AttachedFloor}). The findings and the nodes are spelling the same "
            + $"things at different granularities again.\n{fixture.Report()}");

        Assert.True(
            fixture.Decorated.Unattached.Count <= UnattachedCeiling,
            $"{fixture.Decorated.Unattached.Count} committed-fixture findings could not be placed "
            + $"(ceiling {UnattachedCeiling}).\n{fixture.Report()}");
    }

    /// <summary>
    /// The unattached remainder is the two known gaps and nothing else.
    /// </summary>
    /// <remarks>
    /// Asserted by <em>kind</em>, not by count. A count alone would let a new unattached
    /// dependency finding hide inside the budget the Dockerfile gap already spends; naming the
    /// files means a finding that stops attaching for a new reason shows up as a new file in this
    /// list rather than as a number that is still under its ceiling.
    /// </remarks>
    [CommittedFixtureFact]
    public async Task The_findings_that_do_not_attach_are_the_two_gaps_nothing_models_yet()
    {
        var fixture = await CommittedFixture.BuildAsync();

        var files = fixture.Decorated.Unattached
            .Select(f => StripLine(f.Location) ?? "(no location)")
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

        // Dockerfile: no NodeType models a container build file, so a Checkov/Trivy finding on it
        // has no node to land on. infra/main.tf: lines inside `terraform`/`provider` blocks and
        // inside aws_ecs_service, none of which TerraformResourceTypeMap maps.
        Assert.Equal(["Dockerfile", "infra/main.tf"], files);
    }

    /// <summary>
    /// Finding 18-A, stated as an assertion: the dependency join really is a two-granularity
    /// join, and it really does close.
    /// </summary>
    /// <remarks>
    /// Without the first two assertions this test could pass on a fixture where the two sides
    /// happened to spell the package identically — which would make it a test of nothing. The
    /// version-grained finding ref and the name-grained node key have to be different strings for
    /// the third assertion to mean anything, so that difference is asserted rather than assumed.
    /// </remarks>
    [CommittedFixtureFact]
    public async Task The_dependency_layer_joins_across_a_real_granularity_difference()
    {
        var fixture = await CommittedFixture.BuildAsync();

        // OSV and Trivy both report this package, so there is more than one finding here — but
        // one node ref, because both scanners name the same coordinate and the unifier builds the
        // ref from it.
        var scanned = fixture.Findings
            .Where(f => f.NodeRef.StartsWith("pkg:newtonsoft.json:", StringComparison.Ordinal))
            .ToList();

        Assert.NotEmpty(scanned);

        var findingRef = Assert.Single(scanned.Select(f => f.NodeRef).Distinct(StringComparer.Ordinal));
        var nodeKey = NodeId.Package("newtonsoft.json");

        Assert.Contains(nodeKey, fixture.NodeKeys);
        Assert.NotEqual(findingRef, nodeKey);

        // Both are canonical. Neither side is malformed, nothing would throw, and
        // CanonicalIdMismatchTests' guard is silent on this — which is why the island bug it was
        // written for could not have been caught by it.
        Assert.True(NodeId.IsCanonical(findingRef));
        Assert.True(NodeId.IsCanonical(nodeKey));

        Assert.All(scanned, f => Assert.Contains(f, fixture.Decorated.FindingsByNodeKey[nodeKey]));
    }

    /// <summary>
    /// Finding 19-B, pinned against the committed Terraform: the fixture's deliberately ambiguous
    /// task definition produces an <see cref="Confidence.Unresolved"/> edge rather than vanishing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>infra/main.tf</c> writes <c>image = var.legacy_worker_image</c> — bare, unquoted,
    /// because that is how a Terraform author writes a plain variable reference.
    /// <c>TaskDefinitionImageExtractor</c> used to require the quotes, so this task definition was
    /// absent from its result entirely: no image node, no task node, no edge, and SEC-19's
    /// <c>unresolved</c> tier unreachable by any input the fixture contains.
    /// </para>
    /// <para>
    /// <c>FlagshipChainTests</c> covers the same scenario with a <c>const</c> that writes
    /// <c>image = "${var.legacy_worker_image}"</c> — quoted, which the old pattern <em>did</em>
    /// match. That is the drift this file exists to catch: the constant passed while the committed
    /// fixture did not, and nothing compared them. This assertion reads the real file.
    /// </para>
    /// </remarks>
    [CommittedFixtureFact]
    public async Task The_committed_terraforms_bare_variable_image_still_produces_an_unresolved_join()
    {
        var fixture = await CommittedFixture.BuildAsync();

        var task = NodeId.Task("legacy_worker_task");
        Assert.Contains(task, fixture.NodeKeys);

        var byId = fixture.Nodes.ToDictionary(n => n.Id);
        var deployedAs = Assert.Single(
            fixture.Edges,
            e => e.Relation == "deployed-as" && byId[e.ToNodeId].NodeKey == task);

        Assert.Equal(Confidence.Unresolved, deployedAs.Confidence);
        Assert.Equal(NodeId.Code("orderapp"), byId[deployedAs.FromNodeId].NodeKey);

        // And the flagship task, from the same file and the same extractor pass, is the contrast:
        // a literal image that does normalize to the Dockerfile's label.
        var flagship = Assert.Single(
            fixture.Edges,
            e => e.Relation == "deployed-as" && byId[e.ToNodeId].NodeKey == NodeId.Task("order_task"));

        Assert.Equal(Confidence.Inferred, flagship.Confidence);
    }

    /// <summary>
    /// Every SARIF file the fixture commits is one this solution can read.
    /// </summary>
    /// <remarks>
    /// The <c>osv.sarif</c>/<c>osv.json</c> routing bug (see <c>NormalizationPipeline.Routes</c>)
    /// dropped a whole scanner's findings and looked like a clean scan. A new fixture file nothing
    /// routes would do the same thing, so it fails here instead of quietly lowering the counts
    /// above.
    /// </remarks>
    [CommittedFixtureFact]
    public void Every_committed_sarif_file_routes_to_an_extractor()
    {
        var unroutable = CommittedFixture.ScanOutputFiles()
            .Where(f => CommittedFixture.ExtractorFor(Path.GetFileName(f)) is null)
            .Select(Path.GetFileName)
            .ToList();

        Assert.Empty(unroutable);
        Assert.Equal(5, CommittedFixture.ScanOutputFiles().Count);
    }

    /// <summary>
    /// A layer passes when most of its findings attach — not merely one.
    /// </summary>
    /// <remarks>
    /// "At least one" would be satisfied by a single lucky survivor while the rest of the layer
    /// silently fell off, which is a granularity regression wearing a passing test. Half is the
    /// floor because it sits well below every measured layer (100%, 100%, 83%) and well above what
    /// a genuine granularity break leaves behind, which is nothing.
    /// </remarks>
    private static void AssertLayerAttaches(CommittedFixtureGraph fixture, Layer layer)
    {
        var scanned = fixture.Findings.Where(f => f.Layer == layer).ToList();
        Assert.NotEmpty(scanned);

        var attached = scanned.Count(fixture.IsAttached);

        Assert.True(attached * 2 >= scanned.Count, LayerFailure(fixture, layer, scanned, attached));
    }

    /// <summary>
    /// The failure message a granularity drift has to produce: it names the layer and shows both
    /// sides' keys, because "expected: True, actual: False" over an intersection tells whoever
    /// hits this nothing about which two spellings stopped meeting.
    /// </summary>
    private static string LayerFailure(
        CommittedFixtureGraph fixture, Layer layer, IReadOnlyList<Finding> scanned, int attached)
    {
        var findingRefs = scanned.Select(f => f.NodeRef).Distinct(StringComparer.Ordinal).ToList();
        var nodeKeys = fixture.NodeKeys
            .Where(k => NodeId.TryParse(k, out var type, out _) && TypesFor(layer).Contains(type))
            .ToList();

        return $"""
            Only {attached} of {scanned.Count} {layer} finding(s) attached to a graph node.

            Both sides are canonical and neither throws — they are spelling the same things at two
            granularities, which is the silent island split SEC-47 exists to catch. Compare:

              {layer} finding node refs ({findingRefs.Count} distinct): {Sample(findingRefs)}
              graph node keys of that layer's types ({nodeKeys.Count}): {Sample(nodeKeys)}

            {fixture.Report()}
            """;
    }

    /// <summary>The node types a layer's findings and its structural nodes can carry.</summary>
    private static NodeType[] TypesFor(Layer layer) => layer switch
    {
        Layer.Dep => [NodeType.Pkg],
        Layer.Code => [NodeType.Code],
        _ => [NodeType.Resource, NodeType.Task, NodeType.IamRole, NodeType.Image],
    };

    private static string Sample(IReadOnlyList<string> keys) =>
        keys.Count == 0 ? "(none)" : string.Join(", ", keys.Order(StringComparer.Ordinal).Take(4)) + (keys.Count > 4 ? ", …" : "");

    private static string? StripLine(string? location)
    {
        if (location is null) return null;

        var lastColon = location.LastIndexOf(':');
        return lastColon > 0 && location[(lastColon + 1)..].All(char.IsAsciiDigit)
            ? location[..lastColon]
            : location;
    }
}

/// <summary>
/// The committed fixture, run through the real normalization extractors, the real unifier, the
/// four real seam writers, the real <see cref="TerraformFindingLocator"/> and the real
/// <see cref="GraphDecorator"/>. Only the database and the bundle store are fakes — everything
/// that could disagree about how a node is spelled is the production code.
/// </summary>
internal sealed record CommittedFixtureGraph(
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<GraphNode> Nodes,
    IReadOnlyList<GraphEdge> Edges,
    DecoratedGraph Decorated)
{
    public IReadOnlyCollection<string> NodeKeys { get; } =
        Nodes.Select(n => n.NodeKey).ToHashSet(StringComparer.Ordinal);

    public IReadOnlyCollection<Finding> AttachedFindings { get; } =
        Decorated.FindingsByNodeKey.Values.SelectMany(f => f).ToHashSet();

    public bool IsAttached(Finding finding) => AttachedFindings.Contains(finding);

    /// <summary>
    /// A per-layer breakdown, attached to every failure so the number that moved is visible
    /// without re-running anything.
    /// </summary>
    public string Report()
    {
        var lines = new List<string>
        {
            $"committed fixture: {Findings.Count} unified finding(s), {Nodes.Count} node(s), "
            + $"{Edges.Count} edge(s); {AttachedFindings.Count} attached, {Decorated.Unattached.Count} not",
        };

        foreach (var group in Findings.GroupBy(f => f.Layer).OrderBy(g => g.Key))
        {
            var attached = group.Count(IsAttached);
            var keys = group.Where(IsAttached)
                .SelectMany(f => Decorated.FindingsByNodeKey.Where(e => e.Value.Contains(f)).Select(e => e.Key))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToList();

            lines.Add($"  {group.Key,-5} {attached,3}/{group.Count(),-3} attached over {keys.Count} node(s): "
                      + string.Join(", ", keys.Take(6)) + (keys.Count > 6 ? ", …" : string.Empty));
        }

        return string.Join('\n', lines);
    }
}

internal static class CommittedFixture
{
    private const string Locator = "fake://committed-fixture";

    /// <summary>
    /// The fixture's <c>Dockerfile</c> and <c>packages.lock.json</c> are attributed to the
    /// <c>OrderApp</c> project. The Dockerfile actually sits at the repository root, and no ticket
    /// owns Dockerfile-to-project attribution yet (see <c>ProvisionalCodeNodeResolver</c>'s
    /// remarks) — a project-scoped path is what a real pipeline would pass, and it is what keeps
    /// the Dockerfile's code node the same one the lock file produces. Anything else and the code
    /// layer would fail here for a reason this ticket does not own.
    /// </summary>
    private const string ProjectDockerfilePath = "src/OrderApp/Dockerfile";
    private const string ProjectLockFilePath = "src/OrderApp/packages.lock.json";

    private static readonly IFindingExtractor[] Extractors =
        [new RoslynSarifExtractor(), new OsvExtractor(), new TrivySarifExtractor(), new CheckovSarifExtractor()];

    /// <summary>
    /// Mirrors <c>NormalizationPipeline.Routes</c> — file-name prefix plus extension. Mirrored
    /// rather than reused because that table is private to the pipeline, and mirrored rather than
    /// hand-assigned per file so that a fixture file nothing would route in production does not
    /// silently get routed here.
    /// </summary>
    private static readonly (string Prefix, string Extension, string Tool)[] Routes =
    [
        ("roslyn", ".sarif", ScannerNames.Roslyn),
        ("osv", ".json", ScannerNames.Osv),
        ("osv", ".sarif", ScannerNames.Osv),
        ("trivy", ".sarif", ScannerNames.Trivy),
        ("checkov", ".sarif", ScannerNames.Checkov),
    ];

    public static IReadOnlyList<string> ScanOutputFiles() =>
        [.. Directory.EnumerateFiles(Path.Combine(FixtureRepo.Require(), "scan_out"), "*.sarif").Order(StringComparer.Ordinal)];

    public static IFindingExtractor? ExtractorFor(string fileName)
    {
        foreach (var (prefix, extension, tool) in Routes)
        {
            if (fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                fileName.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
            {
                return Extractors.Single(e => e.SourceTool == tool);
            }
        }

        return null;
    }

    public static async Task<CommittedFixtureGraph> BuildAsync()
    {
        var root = FixtureRepo.Require();
        var findings = Normalize();
        var hcl = HclFiles(root);

        var tenant = findings[0].TenantId;
        var job = findings[0].ScanJobId;

        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var store = new FakeGraphInputsStore { Files = new Dictionary<string, string>(hcl, StringComparer.OrdinalIgnoreCase) };

        await new InfraSpineWriter(
            store,
            new TerraformInfraSpineReader(NullLogger<TerraformInfraSpineReader>.Instance),
            unitOfWork,
            NullLogger<InfraSpineWriter>.Instance)
            .WriteAsync(Locator, tenant, job, CancellationToken.None);

        await new DepCodeSeamWriter(
            new DepCodeSeamReader(NullLogger<DepCodeSeamReader>.Instance),
            unitOfWork,
            NullLogger<DepCodeSeamWriter>.Instance)
            .WriteAsync(
                ProjectLockFilePath,
                await File.ReadAllTextAsync(Path.Combine(root, "src", "OrderApp", "packages.lock.json")),
                tenant, job, CancellationToken.None);

        await new CodeInfraSeamWriter(new CodeInfraSeamReader(), unitOfWork, NullLogger<CodeInfraSeamWriter>.Instance)
            .WriteAsync(
                ProjectDockerfilePath,
                await File.ReadAllTextAsync(Path.Combine(root, "Dockerfile")),
                hcl, tenant, job, CancellationToken.None);

        await new RoleResourceSeamWriter(new RoleResourceSeamReader(), unitOfWork, NullLogger<RoleResourceSeamWriter>.Instance)
            .WriteAsync(hcl, tenant, job, CancellationToken.None);

        var nodes = unitOfWork.FakeRepository<GraphNode>().Added.ToList();
        var edges = unitOfWork.FakeRepository<GraphEdge>().Added.ToList();

        // Exactly what CandidateChainWriter does before it traverses: infra findings are file-and-
        // line-grained and only the Terraform source can say which resource that line is inside.
        var infraLocations = new TerraformFindingLocator(NullLogger<TerraformFindingLocator>.Instance)
            .Locate(hcl, findings.Where(f => f.Layer == Layer.Infra && !string.IsNullOrWhiteSpace(f.Location)).Select(f => f.Location!));

        var decorated = new GraphDecorator(NullLogger<GraphDecorator>.Instance)
            .Decorate(nodes, findings, infraLocations);

        return new CommittedFixtureGraph(findings, nodes, edges, decorated);
    }

    /// <summary>
    /// The fixture's <c>infra/*.tf</c>, keyed the way a stored bundle keys them
    /// (<c>graph-inputs/…</c>). The prefix matters: <see cref="TerraformFindingLocator"/> matches
    /// a scanner's <c>infra/iam.tf</c> against a bundle's <c>graph-inputs/infra/iam.tf</c> by
    /// suffix, and keying these as bare relative paths would test a join the product never makes.
    /// </summary>
    private static Dictionary<string, string> HclFiles(string root)
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in Directory.EnumerateFiles(Path.Combine(root, "infra"), "*.tf").Order(StringComparer.Ordinal))
            files["graph-inputs/infra/" + Path.GetFileName(path)] = File.ReadAllText(path);

        return files;
    }

    /// <summary>
    /// The five committed SARIF files through their real extractors and the real unifier — the
    /// same two steps <c>NormalizationPipeline</c> runs, minus the rule-mapping lookup, which
    /// needs a database and only fills in CWE ids. No node reference depends on a CWE.
    /// </summary>
    private static IReadOnlyList<Finding> Normalize()
    {
        var tenant = Guid.CreateVersion7();
        var job = Guid.CreateVersion7();
        var raw = new List<Finding>();

        foreach (var path in ScanOutputFiles())
        {
            var extractor = ExtractorFor(Path.GetFileName(path))
                ?? throw new InvalidOperationException($"No extractor routes {Path.GetFileName(path)}");

            using var stream = File.OpenRead(path);
            raw.AddRange(extractor.Extract(stream, tenant, job));
        }

        return new FindingUnifier().Unify(raw);
    }
}

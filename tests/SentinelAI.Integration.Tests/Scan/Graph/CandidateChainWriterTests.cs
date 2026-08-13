using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Integration.Tests.Scan.Graph;

/// <summary>
/// SEC-20's persistence half: the stored graph plus this scan's findings, in; <c>chains</c> and
/// <c>chain_hops</c> rows, out. Traversal itself is
/// <c>SentinelAI.Application.Tests.Scan.Graph.ExploitChainTraverserTests</c>'s job — this covers
/// what the writer alone owns: reading the graph back, marking hot nodes, and the row shape.
/// </summary>
public class CandidateChainWriterTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();
    private const string Locator = "fake://bundle";

    private static readonly string PackageKey = NodeId.Package("newtonsoft.json");
    private static readonly string CodeKey = NodeId.Code("orderapp");
    private static readonly string TaskKey = NodeId.Task("order_task");
    private static readonly string RoleKey = NodeId.Role("order_task_role");
    private static readonly string BucketKey = NodeId.Resource("customer_data");

    /// <summary>
    /// The flagship graph as the seam writers would have left it: no hot nodes yet, because
    /// nothing has attached a finding to a node.
    /// </summary>
    private static (List<GraphNode> Nodes, List<GraphEdge> Edges) FlagshipGraph()
    {
        var nodes = new List<GraphNode>
        {
            Node(NodeType.Pkg, "newtonsoft.json", Layer.Dep),
            Node(NodeType.Code, "orderapp", Layer.Code),
            Node(NodeType.Task, "order_task", Layer.Infra),
            Node(NodeType.IamRole, "order_task_role", Layer.Infra),
            Node(NodeType.Resource, "customer_data", Layer.Infra),
        };

        var byKey = nodes.ToDictionary(n => n.NodeKey, StringComparer.Ordinal);

        var edges = new List<GraphEdge>
        {
            Edge(byKey[PackageKey], byKey[CodeKey], "used-by", Seam.DepCode, Confidence.Certain),
            Edge(byKey[CodeKey], byKey[TaskKey], "deployed-as", Seam.CodeInfra, Confidence.Inferred),
            Edge(byKey[TaskKey], byKey[RoleKey], "assumes", Seam.InfraSpine, Confidence.Certain),
            Edge(byKey[RoleKey], byKey[BucketKey], "can-access", Seam.RoleResource, Confidence.Certain),
        };

        return (nodes, edges);
    }

    private static GraphNode Node(NodeType type, string identifier, Layer layer)
    {
        var node = GraphNode.Create(Tenant, Job, type, identifier, layer);
        node.Id = Guid.NewGuid();
        return node;
    }

    private static GraphEdge Edge(GraphNode from, GraphNode to, string relation, Seam seam, Confidence confidence) =>
        new()
        {
            Id = Guid.NewGuid(),
            TenantId = Tenant,
            ScanJobId = Job,
            FromNodeId = from.Id,
            ToNodeId = to.Id,
            Relation = relation,
            Seam = seam,
            Confidence = confidence,
            OrientedAttackDir = true,
        };

    private static Finding Finding(Layer layer, string nodeRef, int severity, string? location = null) =>
        new()
        {
            Id = Guid.NewGuid(),
            TenantId = Tenant,
            ScanJobId = Job,
            SourceTool = "test",
            Layer = layer,
            Severity = severity,
            NodeRef = nodeRef,
            Location = location,
            Message = "test finding",
        };

    private static CandidateChainWriter Writer(
        FakeUnitOfWork unitOfWork, IInfraFindingLocator? locator = null, IBundleStore? bundleStore = null) =>
        new(bundleStore ?? new FakeGraphInputsStore(),
            locator ?? new FakeInfraFindingLocator(),
            new GraphDecorator(NullLogger<GraphDecorator>.Instance),
            new ExploitChainTraverser(NullLogger<ExploitChainTraverser>.Instance),
            unitOfWork,
            NullLogger<CandidateChainWriter>.Instance);

    private static FakeUnitOfWork Seeded(List<GraphNode> nodes, List<GraphEdge> edges)
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        unitOfWork.FakeRepository<GraphNode>().Added.AddRange(nodes);
        unitOfWork.FakeRepository<GraphEdge>().Added.AddRange(edges);
        return unitOfWork;
    }

    [Fact]
    public async Task Persists_the_flagship_chain_with_its_weakest_join()
    {
        var (nodes, edges) = FlagshipGraph();
        var unitOfWork = Seeded(nodes, edges);

        var candidates = await Writer(unitOfWork).WriteAsync(
            Locator,
            [Finding(Layer.Dep, NodeId.Package("newtonsoft.json:12.0.1"), severity: 4)],
            Tenant, Job, CancellationToken.None);

        var candidate = Assert.Single(candidates);
        var chain = Assert.Single(unitOfWork.FakeRepository<Chain>().Added);

        Assert.Equal(Tenant, chain.TenantId);
        Assert.Equal(Job, chain.ScanJobId);
        Assert.Equal(4, chain.HopCount);
        Assert.Equal(1, chain.Priority);
        Assert.Equal(Confidence.Inferred, chain.MinConfidence);
        Assert.Equal(candidate.MinConfidence, chain.MinConfidence);

        Assert.True(unitOfWork.CompleteCallCount > 0);
    }

    /// <summary>
    /// A freshly traversed chain is a path that exists, not an attack that happens. Promotion is
    /// the debate's to make.
    /// </summary>
    [Fact]
    public async Task A_written_chain_is_only_ever_a_candidate()
    {
        var (nodes, edges) = FlagshipGraph();
        var unitOfWork = Seeded(nodes, edges);

        await Writer(unitOfWork).WriteAsync(
            Locator, [Finding(Layer.Dep, NodeId.Package("newtonsoft.json:12.0.1"), 4)], Tenant, Job, CancellationToken.None);

        Assert.All(unitOfWork.FakeRepository<Chain>().Added, c => Assert.Equal(ChainStatus.Candidate, c.Status));
    }

    /// <summary>
    /// One hop per node. The seed hop has no edge — it arrived from nowhere — and a hop on a
    /// node no scanner reported has no finding, which is why <c>finding_id</c> is nullable.
    /// </summary>
    [Fact]
    public async Task Hops_are_ordered_and_carry_their_edge_and_finding_where_there_is_one()
    {
        var (nodes, edges) = FlagshipGraph();
        var unitOfWork = Seeded(nodes, edges);
        var packageFinding = Finding(Layer.Dep, NodeId.Package("newtonsoft.json:12.0.1"), severity: 4);

        await Writer(unitOfWork).WriteAsync(Locator, [packageFinding], Tenant, Job, CancellationToken.None);

        var chain = Assert.Single(unitOfWork.FakeRepository<Chain>().Added);
        var hops = unitOfWork.FakeRepository<ChainHop>().Added
            .Where(h => h.ChainId == chain.Id)
            .OrderBy(h => h.HopOrder)
            .ToList();

        Assert.Equal([0, 1, 2, 3, 4], hops.Select(h => h.HopOrder).ToList());

        Assert.Null(hops[0].EdgeId);
        Assert.Equal(packageFinding.Id, hops[0].FindingId);

        Assert.All(hops.Skip(1), h => Assert.NotNull(h.EdgeId));
        Assert.All(hops.Skip(1), h => Assert.Null(h.FindingId));

        // Empty slots: Red fills the technique, Blue the validation.
        Assert.All(hops, h => Assert.Equal(string.Empty, h.TechniqueId));
        Assert.All(hops, h => Assert.False(h.BlueValidated));
        Assert.All(hops, h => Assert.Equal(Tenant, h.TenantId));
    }

    /// <summary>
    /// The whole point of the decoration step: a finding whose node reference is file-grained
    /// still makes the structural node it is about hot, and that hotness is persisted.
    /// </summary>
    [Fact]
    public async Task Decoration_marks_the_seed_node_hot_and_saves_it()
    {
        var (nodes, edges) = FlagshipGraph();
        var unitOfWork = Seeded(nodes, edges);

        await Writer(unitOfWork).WriteAsync(
            Locator,
            [Finding(Layer.Code, NodeId.Code("src/orderapp/controllers/orderscontroller.cs"), severity: 4)],
            Tenant, Job, CancellationToken.None);

        var code = nodes.Single(n => n.NodeKey == CodeKey);
        Assert.True(code.IsHot);
        Assert.Contains(code, unitOfWork.FakeRepository<GraphNode>().Updated);
        Assert.All(nodes.Where(n => n.NodeKey != CodeKey), n => Assert.False(n.IsHot));
    }

    /// <summary>
    /// The infra path end to end: Checkov reports a line in a policy block, the locator places
    /// it on the role, the role becomes a seed, and the role→bucket chain would follow — except
    /// that a role-to-bucket path never leaves the infra layer, so nothing is written. The
    /// hotness is still real and still saved.
    /// </summary>
    [Fact]
    public async Task An_infra_finding_is_placed_through_the_locator()
    {
        var (nodes, edges) = FlagshipGraph();
        var unitOfWork = Seeded(nodes, edges);
        var locator = new FakeInfraFindingLocator { ["infra/iam.tf:25"] = RoleKey };

        await Writer(unitOfWork, locator).WriteAsync(
            Locator,
            [Finding(Layer.Infra, NodeId.Resource("infra/iam.tf"), severity: 4, location: "infra/iam.tf:25")],
            Tenant, Job, CancellationToken.None);

        Assert.True(nodes.Single(n => n.NodeKey == RoleKey).IsHot);
        Assert.Equal(["infra/iam.tf:25"], locator.Requested);
        Assert.Empty(unitOfWork.FakeRepository<Chain>().Added);
    }

    /// <summary>The bundle is only opened when there is an infra finding needing placement.</summary>
    [Fact]
    public async Task A_scan_with_no_infra_findings_never_opens_the_bundle()
    {
        var (nodes, edges) = FlagshipGraph();
        var unitOfWork = Seeded(nodes, edges);
        var store = new FakeGraphInputsStore();

        await Writer(unitOfWork, bundleStore: store).WriteAsync(
            Locator, [Finding(Layer.Dep, NodeId.Package("newtonsoft.json:12.0.1"), 4)], Tenant, Job, CancellationToken.None);

        Assert.Equal(0, store.OpenCount);
    }

    [Fact]
    public async Task No_stored_graph_means_no_chains_rather_than_a_crash()
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());

        var candidates = await Writer(unitOfWork).WriteAsync(
            Locator, [Finding(Layer.Dep, NodeId.Package("newtonsoft.json:12.0.1"), 4)], Tenant, Job, CancellationToken.None);

        Assert.Empty(candidates);
        Assert.Empty(unitOfWork.FakeRepository<Chain>().Added);
    }

    [Fact]
    public async Task A_graph_nothing_decorates_produces_no_chains()
    {
        var (nodes, edges) = FlagshipGraph();
        var unitOfWork = Seeded(nodes, edges);

        var candidates = await Writer(unitOfWork).WriteAsync(Locator, [], Tenant, Job, CancellationToken.None);

        Assert.Empty(candidates);
        Assert.Empty(unitOfWork.FakeRepository<ChainHop>().Added);
    }

    /// <summary>Only this scan job's rows are read back.</summary>
    [Fact]
    public async Task Another_scan_jobs_graph_is_not_traversed()
    {
        var (nodes, edges) = FlagshipGraph();
        var otherJob = GraphNode.Create(Tenant, Guid.NewGuid(), NodeType.Code, "otherapp", Layer.Code);
        otherJob.Id = Guid.NewGuid();

        var unitOfWork = Seeded([.. nodes, otherJob], edges);

        await Writer(unitOfWork).WriteAsync(
            Locator, [Finding(Layer.Dep, NodeId.Package("newtonsoft.json:12.0.1"), 4)], Tenant, Job, CancellationToken.None);

        Assert.DoesNotContain(unitOfWork.FakeRepository<GraphNode>().Updated, n => n.NodeKey == otherJob.NodeKey);
    }
}

/// <summary>
/// Serves <c>.tf</c> files for the writer's locator step. Separate from <c>FakeBundleStore</c>,
/// which documents graph-input reads as unsupported on purpose.
/// </summary>
internal sealed class FakeGraphInputsStore : IBundleStore
{
    public Dictionary<string, string> Files { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["graph-inputs/infra/iam.tf"] = """resource "aws_iam_role" "order_task_role" { name = "order-task-role" }""",
    };

    /// <summary>
    /// The bundle's <c>findings/</c> half, for callers that run normalization too
    /// (<c>RunGraphStageCommandHandler</c>). Empty by default — the chain writer takes findings
    /// as a parameter and never reads them back.
    /// </summary>
    public Dictionary<string, string> FindingsFiles { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public int OpenCount { get; private set; }

    public Task<IReadOnlyList<StoredBundleFile>> OpenGraphInputsAsync(string locator, CancellationToken ct)
    {
        OpenCount++;
        return Task.FromResult(Materialize(Files));
    }

    public Task<IReadOnlyList<StoredBundleFile>> OpenFindingsAsync(string locator, CancellationToken ct)
        => Task.FromResult(Materialize(FindingsFiles));

    private static IReadOnlyList<StoredBundleFile> Materialize(Dictionary<string, string> files)
        => [.. files.Select(f => new StoredBundleFile(f.Key, Encoding.UTF8.GetBytes(f.Value)))];

    public Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct) => throw new NotSupportedException();
    public Task PurgeAsync(Guid scanJobId, CancellationToken ct) => throw new NotSupportedException();
}

/// <summary>
/// A canned locator. Terraform parsing is
/// <c>SentinelAI.Infrastructure.Tests.Graph.TerraformFindingLocatorTests</c>'s job; what matters
/// here is that the writer asks it about the right locations and trusts its answers.
/// </summary>
internal sealed class FakeInfraFindingLocator : IInfraFindingLocator
{
    private readonly Dictionary<string, string> _answers = new(StringComparer.Ordinal);

    public List<string> Requested { get; } = [];

    public string this[string location] { set => _answers[location] = value; }

    public IReadOnlyDictionary<string, string> Locate(
        IReadOnlyDictionary<string, string> hclFiles, IEnumerable<string> findingLocations)
    {
        Requested.AddRange(findingLocations);
        return _answers;
    }
}

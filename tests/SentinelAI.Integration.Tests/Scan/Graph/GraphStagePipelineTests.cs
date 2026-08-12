using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Integration.Tests.Scan.Graph;

/// <summary>
/// The graph stage as one callable unit — what <c>POST /v1/scans/{id}/graph</c> runs. The seams
/// and the traversal have their own tests; this covers what only this class does: reading a
/// bundle's <c>graph-inputs/</c> apart into the three shapes the seams consume, and deciding
/// which project a Dockerfile belongs to.
/// </summary>
public class GraphStagePipelineTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();
    private const string Locator = "fake://bundle";

    private const string Dockerfile = """
        FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
        LABEL org.sentinelai.image="tinyapp/order"
        """;

    private const string LockFile = """
        {"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.1"}}}}
        """;

    private const string MainTf = """
        resource "aws_ecs_task_definition" "order_task" {
          family        = "order-task"
          task_role_arn = aws_iam_role.order_task_role.arn

          container_definitions = jsonencode([
            { name = "order-service", image = "registry.hub.docker.com/tinyapp/order:1.4.2" }
          ])
        }

        resource "aws_iam_role" "order_task_role" {
          name = "order-task-role"
        }
        """;

    /// <summary>
    /// The layout the Action's <c>collect-graph-inputs.sh</c> actually produces: everything under
    /// <c>graph-inputs/</c>, repo-relative paths preserved, the fixture's Dockerfile at the root.
    /// </summary>
    private static Dictionary<string, string> BundleFiles() => new(StringComparer.OrdinalIgnoreCase)
    {
        ["graph-inputs/infra/main.tf"] = MainTf,
        ["graph-inputs/Dockerfile"] = Dockerfile,
        ["graph-inputs/src/OrderApp/packages.lock.json"] = LockFile,
        ["graph-inputs/src/OrderApp/OrderApp.csproj"] = "<Project />",
    };

    private static (GraphStagePipeline Pipeline, FakeUnitOfWork UnitOfWork) Build(
        Dictionary<string, string>? files = null)
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var store = new FakeGraphInputsStore { Files = files ?? BundleFiles() };

        var pipeline = new GraphStagePipeline(
            store,
            new InfraSpineWriter(
                store,
                new TerraformInfraSpineReader(NullLogger<TerraformInfraSpineReader>.Instance),
                unitOfWork,
                NullLogger<InfraSpineWriter>.Instance),
            new DepCodeSeamWriter(
                new DepCodeSeamReader(NullLogger<DepCodeSeamReader>.Instance),
                unitOfWork,
                NullLogger<DepCodeSeamWriter>.Instance),
            new CodeInfraSeamWriter(new CodeInfraSeamReader(), unitOfWork, NullLogger<CodeInfraSeamWriter>.Instance),
            new RoleResourceSeamWriter(new RoleResourceSeamReader(), unitOfWork, NullLogger<RoleResourceSeamWriter>.Instance),
            new CandidateChainWriter(
                store,
                new TerraformFindingLocator(NullLogger<TerraformFindingLocator>.Instance),
                new GraphDecorator(NullLogger<GraphDecorator>.Instance),
                new ExploitChainTraverser(NullLogger<ExploitChainTraverser>.Instance),
                unitOfWork,
                NullLogger<CandidateChainWriter>.Instance),
            NullLogger<GraphStagePipeline>.Instance);

        return (pipeline, unitOfWork);
    }

    private static Finding PackageFinding() => new()
    {
        Id = Guid.NewGuid(),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = "osv",
        Layer = Layer.Dep,
        Severity = 4,
        NodeRef = NodeId.Package("newtonsoft.json:12.0.1"),
        Location = "Newtonsoft.Json@12.0.1",
        Message = "CVE-2024-21907",
    };

    [Fact]
    public async Task Sorts_the_bundles_graph_inputs_into_the_shapes_each_seam_consumes()
    {
        var (pipeline, _) = Build();

        var result = await pipeline.RunAsync(Locator, [PackageFinding()], Tenant, Job, CancellationToken.None);

        Assert.Equal(1, result.TerraformFileCount);
        Assert.Equal(1, result.LockFileCount);
        Assert.Equal(1, result.DockerfileCount);
    }

    /// <summary>
    /// The attribution rule, and the reason this class owns it: the fixture's Dockerfile is at
    /// the repository root while its project is in <c>src/OrderApp/</c>. Deriving the Code node
    /// from the Dockerfile's own path would produce <c>code:dockerfile</c>, and the dep→code and
    /// code→infra seams would build two unconnected halves of one project.
    /// </summary>
    [Fact]
    public async Task A_root_dockerfile_is_attributed_to_the_bundles_only_project()
    {
        var (pipeline, unitOfWork) = Build();

        await pipeline.RunAsync(Locator, [PackageFinding()], Tenant, Job, CancellationToken.None);

        var nodes = unitOfWork.FakeRepository<GraphNode>().Added;
        Assert.Contains(nodes, n => n.NodeKey == NodeId.Code("OrderApp"));
        Assert.DoesNotContain(nodes, n => n.NodeKey == NodeId.Code("Dockerfile"));
    }

    /// <summary>A Dockerfile beside its own lock file needs no inference at all.</summary>
    [Fact]
    public async Task A_dockerfile_beside_its_project_uses_its_own_path()
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["graph-inputs/infra/main.tf"] = MainTf,
            ["graph-inputs/src/OrderApp/Dockerfile"] = Dockerfile,
            ["graph-inputs/src/OrderApp/packages.lock.json"] = LockFile,
        };

        var (pipeline, unitOfWork) = Build(files);

        await pipeline.RunAsync(Locator, [PackageFinding()], Tenant, Job, CancellationToken.None);

        Assert.Contains(unitOfWork.FakeRepository<GraphNode>().Added, n => n.NodeKey == NodeId.Code("OrderApp"));
    }

    /// <summary>The whole point: one call over one bundle produces the flagship chain.</summary>
    [Fact]
    public async Task One_run_over_a_bundle_produces_the_cross_layer_chain()
    {
        var (pipeline, unitOfWork) = Build();

        var result = await pipeline.RunAsync(Locator, [PackageFinding()], Tenant, Job, CancellationToken.None);

        // Two maximal paths leave the hot package: the one through the workload to its role, and
        // the shorter one that dead-ends at the image node the name match produced.
        var chain = Assert.Single(result.Chains, c => c.Target.Node.NodeKey == NodeId.Role("order_task_role"));

        Assert.Equal(
            [NodeId.Package("newtonsoft.json"), NodeId.Code("OrderApp"), NodeId.Task("order_task"), NodeId.Role("order_task_role")],
            chain.Hops.Select(h => h.Node.NodeKey).ToList());

        Assert.Equal(Confidence.Inferred, chain.MinConfidence);
        Assert.Contains(unitOfWork.FakeRepository<Chain>().Added, c => c.HopCount == chain.HopCount);
        Assert.Equal(result.Chains.Count, unitOfWork.FakeRepository<Chain>().Added.Count);
    }

    /// <summary>
    /// A bundle the runner built without Terraform still normalizes and still builds the dep→code
    /// seam. Fewer edges, no crash, and the log says why.
    /// </summary>
    [Fact]
    public async Task A_bundle_with_no_terraform_still_builds_what_it_can()
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["graph-inputs/src/OrderApp/packages.lock.json"] = LockFile,
        };

        var (pipeline, unitOfWork) = Build(files);

        var result = await pipeline.RunAsync(Locator, [PackageFinding()], Tenant, Job, CancellationToken.None);

        Assert.Equal(0, result.TerraformFileCount);
        Assert.Contains(unitOfWork.FakeRepository<GraphNode>().Added, n => n.NodeKey == NodeId.Package("newtonsoft.json"));

        // dep→code is one layer crossing, but the chain needs a hot seed on one end and a second
        // layer on the other — here the package is hot and the code node is the second layer.
        Assert.Single(result.Chains);
    }

    [Fact]
    public async Task An_empty_bundle_produces_nothing_rather_than_throwing()
    {
        var (pipeline, unitOfWork) = Build(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

        var result = await pipeline.RunAsync(Locator, [PackageFinding()], Tenant, Job, CancellationToken.None);

        Assert.Empty(result.Chains);
        Assert.Empty(unitOfWork.FakeRepository<Chain>().Added);
    }
}

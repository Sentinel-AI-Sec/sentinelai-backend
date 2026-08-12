using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Graph;
using SentinelAI.Infrastructure.Implementation.Repositories;

namespace SentinelAI.Integration.Tests.Scan.Graph;

/// <summary>
/// A real <c>.tar.gz</c> on disk, through the real <see cref="FileSystemBundleStore"/>, into
/// candidate chains — the path <c>POST /v1/scans/{id}/graph</c> takes, and the one
/// <c>postman/build-fixture-bundle.sh</c> produces bundles for.
/// </summary>
/// <remarks>
/// Everything above this level is covered elsewhere with an in-memory store. What only this
/// test covers is the tar layer: entry names written as <c>./graph-inputs/...</c> (which is what
/// <c>tar -czf out.tar.gz -C stage .</c> emits), path separators, and the prefix matching that
/// decides whether the graph stage sees any inputs at all. A mismatch there produces an empty
/// graph and no error — the same silent shape as the island bug, one layer down.
/// </remarks>
public class BundleToChainsTests : IDisposable
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private readonly string _root = Path.Combine(Path.GetTempPath(), $"sentinelai-tests-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
        GC.SuppressFinalize(this);
    }

    private const string Dockerfile = """
        FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
        LABEL org.sentinelai.image="tinyapp/order"
        """;

    private const string LockFile = """
        {"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.1"}}}}
        """;

    private const string InfraTf = """
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

        resource "aws_iam_role_policy" "order_task_policy" {
          role = aws_iam_role.order_task_role.id

          policy = jsonencode({
            Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }]
          })
        }

        resource "aws_s3_bucket" "customer_data" {
          bucket = "sentinelai-fixture-customer-data"
        }
        """;

    /// <summary>
    /// Writes a bundle with <c>./</c>-prefixed entry names, exactly as
    /// <c>tar -czf bundle.tar.gz -C stage .</c> writes them.
    /// </summary>
    private string WriteBundle()
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "bundle.tar.gz");

        using var archive = TarGzTestHelper.Build(new Dictionary<string, string>
        {
            ["./metadata.json"] = """{"project_id":"11111111-1111-1111-1111-111111111111"}""",
            ["./findings/osv.sarif"] = "{}",
            ["./graph-inputs/infra/main.tf"] = InfraTf,
            ["./graph-inputs/Dockerfile"] = Dockerfile,
            ["./graph-inputs/src/OrderApp/packages.lock.json"] = LockFile,
        });

        using var file = File.Create(path);
        archive.CopyTo(file);

        return path;
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
    public async Task A_bundle_on_disk_becomes_candidate_chains()
    {
        var locator = WriteBundle();
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());

        var store = new FileSystemBundleStore(
            Options.Create(new BundleStorageOptions { RootPath = _root }),
            NullLogger<FileSystemBundleStore>.Instance);

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

        var result = await pipeline.RunAsync(locator, [PackageFinding()], Tenant, Job, CancellationToken.None);

        // The tar layer did not swallow the inputs.
        Assert.Equal(1, result.TerraformFileCount);
        Assert.Equal(1, result.LockFileCount);
        Assert.Equal(1, result.DockerfileCount);

        var flagship = Assert.Single(
            result.Chains, c => c.Target.Node.NodeKey == NodeId.Resource("customer_data"));

        Assert.Equal(
            [
                NodeId.Package("newtonsoft.json"),
                NodeId.Code("OrderApp"),
                NodeId.Task("order_task"),
                NodeId.Role("order_task_role"),
                NodeId.Resource("customer_data"),
            ],
            flagship.Hops.Select(h => h.Node.NodeKey).ToList());

        Assert.Equal(Confidence.Inferred, flagship.MinConfidence);
        Assert.Equal(1, flagship.Priority);
        Assert.NotEmpty(unitOfWork.FakeRepository<Chain>().Added);
    }

    /// <summary>
    /// A bundle whose graph inputs the store cannot see would produce zero chains and no error.
    /// This pins that the prefix match is what is doing the work, not luck.
    /// </summary>
    [Fact]
    public async Task Graph_inputs_are_read_back_with_their_repo_relative_paths()
    {
        var locator = WriteBundle();

        var store = new FileSystemBundleStore(
            Options.Create(new BundleStorageOptions { RootPath = _root }),
            NullLogger<FileSystemBundleStore>.Instance);

        var files = await store.OpenGraphInputsAsync(locator, CancellationToken.None);

        Assert.Equal(
            ["graph-inputs/Dockerfile", "graph-inputs/infra/main.tf", "graph-inputs/src/OrderApp/packages.lock.json"],
            files.Select(f => f.Name).Order(StringComparer.Ordinal).ToList());
    }
}

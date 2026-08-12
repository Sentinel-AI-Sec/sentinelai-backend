using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Integration.Tests.Scan.Graph;

/// <summary>
/// SEC-19's persistence half. Uses a canned <see cref="ICodeInfraSeamReader"/> — image-name
/// extraction, normalization, and confidence scoring are
/// <c>SentinelAI.Infrastructure.Tests.Graph.CodeInfraSeamReaderTests</c>'s job; this covers the
/// writer's own responsibility: resolving edges to real ids while passing the reader's per-edge
/// <see cref="Confidence"/> through unchanged (unlike the other two seam writers, which stamp a
/// fixed confidence themselves) — same shape as <c>InfraSpineWriterTests</c>.
/// </summary>
public class CodeInfraSeamWriterTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();
    private const string ProjectFilePath = "src/OrderService/Dockerfile";

    private static readonly string CodeKey = NodeId.Code("OrderService");
    private static readonly string ImageKey = NodeId.Image("tinyapp/order");

    [Fact]
    public async Task Persists_nodes_and_carries_the_readers_inferred_confidence_through_unchanged()
    {
        var code = GraphNode.Create(Tenant, Job, NodeType.Code, "OrderService", Layer.Code);
        code.Id = Guid.NewGuid();
        var image = GraphNode.Create(Tenant, Job, NodeType.Image, "tinyapp/order", Layer.Infra);
        image.Id = Guid.NewGuid();

        var result = new CodeInfraSeamReadResult(
            Nodes: [code, image],
            Edges: [new CodeInfraSeamEdge(CodeKey, ImageKey, "runs-as", Confidence.Inferred, ResolvedVariable: false)]);

        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var writer = new CodeInfraSeamWriter(
            new FakeCodeInfraSeamReader(result), unitOfWork, NullLogger<CodeInfraSeamWriter>.Instance);

        await writer.WriteAsync(ProjectFilePath, "FROM x", new Dictionary<string, string>(), Tenant, Job, CancellationToken.None);

        var edge = Assert.Single(unitOfWork.FakeRepository<GraphEdge>().Added);
        Assert.Equal(code.Id, edge.FromNodeId);
        Assert.Equal(image.Id, edge.ToNodeId);
        Assert.Equal(Seam.CodeInfra, edge.Seam);
        Assert.Equal(Confidence.Inferred, edge.Confidence);
        Assert.Equal("runs-as", edge.Relation);

        Assert.True(unitOfWork.CompleteCallCount > 0);
    }

    [Fact]
    public async Task An_unresolved_edge_is_persisted_not_dropped()
    {
        var code = GraphNode.Create(Tenant, Job, NodeType.Code, "OrderService", Layer.Code);
        code.Id = Guid.NewGuid();
        var image = GraphNode.Create(Tenant, Job, NodeType.Image, "tinyapp/order-worker", Layer.Infra);
        image.Id = Guid.NewGuid();

        var result = new CodeInfraSeamReadResult(
            Nodes: [code, image],
            Edges: [new CodeInfraSeamEdge(CodeKey, image.NodeKey, "runs-as", Confidence.Unresolved, ResolvedVariable: false)]);

        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var writer = new CodeInfraSeamWriter(
            new FakeCodeInfraSeamReader(result), unitOfWork, NullLogger<CodeInfraSeamWriter>.Instance);

        await writer.WriteAsync(ProjectFilePath, "FROM x", new Dictionary<string, string>(), Tenant, Job, CancellationToken.None);

        var edge = Assert.Single(unitOfWork.FakeRepository<GraphEdge>().Added);
        Assert.Equal(Confidence.Unresolved, edge.Confidence);
    }

    [Fact]
    public async Task A_node_key_collision_keeps_the_existing_row_instead_of_inserting_a_duplicate()
    {
        var existingCode = GraphNode.Create(Tenant, Job, NodeType.Code, "OrderService", Layer.Code);
        existingCode.Id = Guid.NewGuid();

        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        unitOfWork.FakeRepository<GraphNode>().Added.Add(existingCode);

        var duplicateCode = GraphNode.Create(Tenant, Job, NodeType.Code, "OrderService", Layer.Code);
        duplicateCode.Id = Guid.NewGuid();
        var image = GraphNode.Create(Tenant, Job, NodeType.Image, "tinyapp/order", Layer.Infra);
        image.Id = Guid.NewGuid();

        var result = new CodeInfraSeamReadResult(
            Nodes: [duplicateCode, image],
            Edges: [new CodeInfraSeamEdge(CodeKey, ImageKey, "runs-as", Confidence.Inferred, ResolvedVariable: false)]);

        var writer = new CodeInfraSeamWriter(
            new FakeCodeInfraSeamReader(result), unitOfWork, NullLogger<CodeInfraSeamWriter>.Instance);

        await writer.WriteAsync(ProjectFilePath, "FROM x", new Dictionary<string, string>(), Tenant, Job, CancellationToken.None);

        var nodes = unitOfWork.FakeRepository<GraphNode>().Added;
        Assert.Equal(2, nodes.Count);
        Assert.DoesNotContain(duplicateCode, nodes);

        var edge = Assert.Single(unitOfWork.FakeRepository<GraphEdge>().Added);
        Assert.Equal(existingCode.Id, edge.FromNodeId);
    }

    private sealed class FakeCodeInfraSeamReader(CodeInfraSeamReadResult result) : ICodeInfraSeamReader
    {
        public CodeInfraSeamReadResult Read(CodeInfraSeamInput input, Guid tenantId, Guid scanJobId) => result;
    }
}

using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Integration.Tests.Scan.Graph;

/// <summary>
/// SEC-18 part A's persistence half. Uses a canned <see cref="IDepCodeSeamReader"/> — lock-file
/// parsing correctness is <c>SentinelAI.Infrastructure.Tests.Graph.DepCodeSeamReaderTests</c>'s
/// job; this covers what only the writer is responsible for: resolving node-key-addressed edges
/// to real database ids and the upsert-not-crash behavior on a (ScanJobId, NodeKey) collision —
/// same shape as <c>InfraSpineWriterTests</c>.
/// </summary>
public class DepCodeSeamWriterTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();
    private const string ProjectFilePath = "src/OrderService/packages.lock.json";

    private static readonly string PkgKey = NodeId.Package("Newtonsoft.Json");
    private static readonly string CodeKey = NodeId.Code("OrderService");

    [Fact]
    public async Task Persists_nodes_and_resolves_the_used_by_edge_to_real_database_ids()
    {
        var pkg = GraphNode.Create(Tenant, Job, NodeType.Pkg, "Newtonsoft.Json", Layer.Dep);
        pkg.Id = Guid.NewGuid();
        var code = GraphNode.Create(Tenant, Job, NodeType.Code, "OrderService", Layer.Code);
        code.Id = Guid.NewGuid();

        var result = new DepCodeSeamReadResult(
            Nodes: [pkg, code],
            Edges: [new DepCodeSeamEdge(PkgKey, CodeKey, "used-by")]);

        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var writer = new DepCodeSeamWriter(
            new FakeDepCodeSeamReader(result), unitOfWork, NullLogger<DepCodeSeamWriter>.Instance);

        await writer.WriteAsync(ProjectFilePath, "{}", Tenant, Job, CancellationToken.None);

        Assert.Equal(2, unitOfWork.FakeRepository<GraphNode>().Added.Count);

        var edge = Assert.Single(unitOfWork.FakeRepository<GraphEdge>().Added);
        Assert.Equal(pkg.Id, edge.FromNodeId);
        Assert.Equal(code.Id, edge.ToNodeId);
        Assert.Equal(Seam.DepCode, edge.Seam);
        Assert.Equal(Confidence.Certain, edge.Confidence);
        Assert.Equal("used-by", edge.Relation);
        Assert.Equal(Tenant, edge.TenantId);
        Assert.Equal(Job, edge.ScanJobId);

        Assert.True(unitOfWork.CompleteCallCount > 0);
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
        var pkg = GraphNode.Create(Tenant, Job, NodeType.Pkg, "Newtonsoft.Json", Layer.Dep);
        pkg.Id = Guid.NewGuid();

        var result = new DepCodeSeamReadResult(
            Nodes: [pkg, duplicateCode],
            Edges: [new DepCodeSeamEdge(PkgKey, CodeKey, "used-by")]);

        var writer = new DepCodeSeamWriter(
            new FakeDepCodeSeamReader(result), unitOfWork, NullLogger<DepCodeSeamWriter>.Instance);

        await writer.WriteAsync(ProjectFilePath, "{}", Tenant, Job, CancellationToken.None);

        var nodes = unitOfWork.FakeRepository<GraphNode>().Added;
        Assert.Equal(2, nodes.Count); // existingCode (seeded) + pkg
        Assert.DoesNotContain(duplicateCode, nodes);

        var edge = Assert.Single(unitOfWork.FakeRepository<GraphEdge>().Added);
        Assert.Equal(existingCode.Id, edge.ToNodeId);
    }

    [Fact]
    public async Task An_edge_whose_endpoint_never_resolved_is_skipped_not_thrown()
    {
        var pkg = GraphNode.Create(Tenant, Job, NodeType.Pkg, "Newtonsoft.Json", Layer.Dep);
        pkg.Id = Guid.NewGuid();

        // References a Code node key that was never in Nodes — shouldn't happen from the real
        // reader, but the writer must degrade rather than crash if it ever does.
        var result = new DepCodeSeamReadResult(
            Nodes: [pkg],
            Edges: [new DepCodeSeamEdge(PkgKey, CodeKey, "used-by")]);

        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var writer = new DepCodeSeamWriter(
            new FakeDepCodeSeamReader(result), unitOfWork, NullLogger<DepCodeSeamWriter>.Instance);

        await writer.WriteAsync(ProjectFilePath, "{}", Tenant, Job, CancellationToken.None);

        Assert.Empty(unitOfWork.FakeRepository<GraphEdge>().Added);
    }

    private sealed class FakeDepCodeSeamReader(DepCodeSeamReadResult result) : IDepCodeSeamReader
    {
        public DepCodeSeamReadResult Read(DepCodeSeamInput input, Guid tenantId, Guid scanJobId) => result;
    }
}

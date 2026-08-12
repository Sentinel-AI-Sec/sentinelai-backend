using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Integration.Tests.Scan.Graph;

/// <summary>
/// SEC-17's persistence half. Uses a canned <see cref="IInfraSpineReader"/> rather than the
/// real Terraform parser — DOT/HCL parsing correctness is
/// <c>SentinelAI.Infrastructure.Tests.Graph.TerraformInfraSpineReaderTests</c>'s job; this
/// covers what only the writer is responsible for: turning node-key-addressed edges into real
/// database ids, and the upsert-not-crash behavior on a (ScanJobId, NodeKey) collision.
/// </summary>
public class InfraSpineWriterTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();
    private const string Locator = "fake://bundle";

    private static readonly string RoleKey = NodeId.For(NodeType.IamRole, "order_task_role");
    private static readonly string TaskKey = NodeId.For(NodeType.Task, "order_task");

    [Fact]
    public async Task Persists_nodes_and_resolves_edges_to_real_database_ids()
    {
        var role = GraphNode.Create(Tenant, Job, NodeType.IamRole, "order_task_role", Layer.Infra);
        role.Id = Guid.NewGuid();
        var task = GraphNode.Create(Tenant, Job, NodeType.Task, "order_task", Layer.Infra);
        task.Id = Guid.NewGuid();

        var result = new InfraSpineReadResult(
            Nodes: [role, task],
            Edges: [new InfraSpineEdge(RoleKey, TaskKey, "can-access", OrientedAttackDir: true)],
            UsedHclFallback: false);

        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var writer = new InfraSpineWriter(
            new FakeGraphInputsBundleStore(), new FakeInfraSpineReader(result), unitOfWork,
            NullLogger<InfraSpineWriter>.Instance);

        await writer.WriteAsync(Locator, Tenant, Job, CancellationToken.None);

        var nodes = unitOfWork.FakeRepository<GraphNode>().Added;
        Assert.Equal(2, nodes.Count);

        var edges = unitOfWork.FakeRepository<GraphEdge>().Added;
        var edge = Assert.Single(edges);
        Assert.Equal(role.Id, edge.FromNodeId);
        Assert.Equal(task.Id, edge.ToNodeId);
        Assert.Equal(Seam.InfraSpine, edge.Seam);
        Assert.Equal(Confidence.Certain, edge.Confidence);
        Assert.True(edge.OrientedAttackDir);
        Assert.Equal("can-access", edge.Relation);
        Assert.Equal(Tenant, edge.TenantId);
        Assert.Equal(Job, edge.ScanJobId);

        Assert.True(unitOfWork.CompleteCallCount > 0);
    }

    [Fact]
    public async Task A_node_key_collision_keeps_the_existing_row_instead_of_inserting_a_duplicate()
    {
        var existingRole = GraphNode.Create(Tenant, Job, NodeType.IamRole, "order_task_role", Layer.Infra);
        existingRole.Id = Guid.NewGuid();

        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        // Seed as if a previous write already persisted this exact node for this scan job.
        unitOfWork.FakeRepository<GraphNode>().Added.Add(existingRole);

        // A second, distinct GraphNode instance that happens to canonicalize to the same key —
        // the in-flight equivalent of two extractors disagreeing on one canonical id.
        var duplicateRole = GraphNode.Create(Tenant, Job, NodeType.IamRole, "order_task_role", Layer.Infra);
        duplicateRole.Id = Guid.NewGuid();
        var task = GraphNode.Create(Tenant, Job, NodeType.Task, "order_task", Layer.Infra);
        task.Id = Guid.NewGuid();

        var result = new InfraSpineReadResult(
            Nodes: [duplicateRole, task],
            Edges: [new InfraSpineEdge(RoleKey, TaskKey, "can-access", OrientedAttackDir: true)],
            UsedHclFallback: false);

        var writer = new InfraSpineWriter(
            new FakeGraphInputsBundleStore(), new FakeInfraSpineReader(result), unitOfWork,
            NullLogger<InfraSpineWriter>.Instance);

        await writer.WriteAsync(Locator, Tenant, Job, CancellationToken.None);

        // Only the new task node was added — the role was already there under existingRole.Id.
        var nodes = unitOfWork.FakeRepository<GraphNode>().Added;
        Assert.Equal(2, nodes.Count); // existingRole (seeded) + task
        Assert.DoesNotContain(duplicateRole, nodes);

        // The edge resolved against the pre-existing row's id, not the dropped duplicate's.
        var edge = Assert.Single(unitOfWork.FakeRepository<GraphEdge>().Added);
        Assert.Equal(existingRole.Id, edge.FromNodeId);
        Assert.NotEqual(duplicateRole.Id, edge.FromNodeId);
    }

    [Fact]
    public async Task An_edge_whose_endpoint_never_resolved_is_skipped_not_thrown()
    {
        var task = GraphNode.Create(Tenant, Job, NodeType.Task, "order_task", Layer.Infra);

        // References a role node key that was never in Nodes — shouldn't happen from the real
        // reader, but the writer must degrade rather than crash if it ever does.
        var result = new InfraSpineReadResult(
            Nodes: [task],
            Edges: [new InfraSpineEdge(RoleKey, TaskKey, "can-access", OrientedAttackDir: true)],
            UsedHclFallback: false);

        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var writer = new InfraSpineWriter(
            new FakeGraphInputsBundleStore(), new FakeInfraSpineReader(result), unitOfWork,
            NullLogger<InfraSpineWriter>.Instance);

        await writer.WriteAsync(Locator, Tenant, Job, CancellationToken.None);

        Assert.Empty(unitOfWork.FakeRepository<GraphEdge>().Added);
    }

    private sealed class FakeGraphInputsBundleStore : IBundleStore
    {
        public Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct)
            => throw new NotSupportedException();

        public Task<IReadOnlyList<StoredBundleFile>> OpenFindingsAsync(string locator, CancellationToken ct)
            => throw new NotSupportedException();

        public Task<IReadOnlyList<StoredBundleFile>> OpenGraphInputsAsync(string locator, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<StoredBundleFile>>([]);

        public Task PurgeAsync(Guid scanJobId, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class FakeInfraSpineReader(InfraSpineReadResult result) : IInfraSpineReader
    {
        public InfraSpineReadResult Read(InfraSpineInput input, Guid tenantId, Guid scanJobId) => result;
    }
}

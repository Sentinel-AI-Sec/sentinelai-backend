using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Integration.Tests.Scan.Graph;

/// <summary>
/// SEC-18 part B's persistence half. Uses a canned <see cref="IRoleResourceSeamReader"/> — IAM
/// policy parsing and wildcard-widening correctness are
/// <c>SentinelAI.Infrastructure.Tests.Graph.RoleResourceSeamReaderTests</c>'s job; this covers
/// the writer's own responsibility: resolving edges to real ids, stamping
/// <c>Seam.RoleResource</c>/<c>Confidence.Certain</c>, and the upsert-not-crash collision
/// behavior — same shape as <c>InfraSpineWriterTests</c>.
/// </summary>
public class RoleResourceSeamWriterTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private static readonly string RoleKey = NodeId.Role("order_task_role");
    private static readonly string ResourceKey = NodeId.Resource("customer_data");

    [Fact]
    public async Task Persists_nodes_and_resolves_the_widened_can_access_edge_to_real_database_ids()
    {
        var role = GraphNode.Create(Tenant, Job, NodeType.IamRole, "order_task_role", Layer.Infra);
        role.Id = Guid.NewGuid();
        var resource = GraphNode.Create(Tenant, Job, NodeType.Resource, "customer_data", Layer.Infra);
        resource.Id = Guid.NewGuid();

        var result = new RoleResourceSeamReadResult(
            Nodes: [role, resource],
            Edges: [new RoleResourceSeamEdge(RoleKey, ResourceKey, "can-access", Widened: true)]);

        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var writer = new RoleResourceSeamWriter(
            new FakeRoleResourceSeamReader(result), unitOfWork, NullLogger<RoleResourceSeamWriter>.Instance);

        await writer.WriteAsync(new Dictionary<string, string>(), Tenant, Job, CancellationToken.None);

        Assert.Equal(2, unitOfWork.FakeRepository<GraphNode>().Added.Count);

        var edge = Assert.Single(unitOfWork.FakeRepository<GraphEdge>().Added);
        Assert.Equal(role.Id, edge.FromNodeId);
        Assert.Equal(resource.Id, edge.ToNodeId);
        Assert.Equal(Seam.RoleResource, edge.Seam);
        Assert.Equal(Confidence.Certain, edge.Confidence);
        Assert.Equal("can-access", edge.Relation);

        Assert.True(unitOfWork.CompleteCallCount > 0);
    }

    [Fact]
    public async Task A_node_key_collision_keeps_the_existing_row_instead_of_inserting_a_duplicate()
    {
        var existingRole = GraphNode.Create(Tenant, Job, NodeType.IamRole, "order_task_role", Layer.Infra);
        existingRole.Id = Guid.NewGuid();

        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        unitOfWork.FakeRepository<GraphNode>().Added.Add(existingRole);

        var duplicateRole = GraphNode.Create(Tenant, Job, NodeType.IamRole, "order_task_role", Layer.Infra);
        duplicateRole.Id = Guid.NewGuid();
        var resource = GraphNode.Create(Tenant, Job, NodeType.Resource, "customer_data", Layer.Infra);
        resource.Id = Guid.NewGuid();

        var result = new RoleResourceSeamReadResult(
            Nodes: [duplicateRole, resource],
            Edges: [new RoleResourceSeamEdge(RoleKey, ResourceKey, "can-access", Widened: true)]);

        var writer = new RoleResourceSeamWriter(
            new FakeRoleResourceSeamReader(result), unitOfWork, NullLogger<RoleResourceSeamWriter>.Instance);

        await writer.WriteAsync(new Dictionary<string, string>(), Tenant, Job, CancellationToken.None);

        var nodes = unitOfWork.FakeRepository<GraphNode>().Added;
        Assert.Equal(2, nodes.Count);
        Assert.DoesNotContain(duplicateRole, nodes);

        var edge = Assert.Single(unitOfWork.FakeRepository<GraphEdge>().Added);
        Assert.Equal(existingRole.Id, edge.FromNodeId);
    }

    private sealed class FakeRoleResourceSeamReader(RoleResourceSeamReadResult result) : IRoleResourceSeamReader
    {
        public RoleResourceSeamReadResult Read(RoleResourceSeamInput input, Guid tenantId, Guid scanJobId) => result;
    }
}

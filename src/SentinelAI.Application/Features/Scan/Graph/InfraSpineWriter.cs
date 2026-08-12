using System.Text;
using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Graph;

/// <summary>
/// SEC-17: reads a bundle's Terraform graph inputs, builds the infra spine
/// (<see cref="IInfraSpineReader"/>), and persists it as <see cref="GraphNode"/>/
/// <see cref="GraphEdge"/> rows. The reader itself (Infrastructure) is pure — no database — so
/// this class owns the one part of the ticket that needs one: the upsert against
/// (<c>ScanJobId</c>, <c>NodeKey</c>), which is where the "island bug" (two extractors
/// disagreeing on a canonical id) would actually surface as a unique-constraint violation if
/// left unhandled.
/// </summary>
public sealed class InfraSpineWriter(
    IBundleStore bundleStore,
    IInfraSpineReader reader,
    IUnitOfWork unitOfWork,
    ILogger<InfraSpineWriter> logger)
{
    public async Task WriteAsync(string bundleLocator, Guid tenantId, Guid scanJobId, CancellationToken ct)
    {
        var files = await bundleStore.OpenGraphInputsAsync(bundleLocator, ct);

        string? dotText = null;
        var hclFiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            if (file.Name.EndsWith(".dot", StringComparison.OrdinalIgnoreCase))
                dotText = Encoding.UTF8.GetString(file.Content);
            else if (file.Name.EndsWith(".tf", StringComparison.OrdinalIgnoreCase))
                hclFiles[file.Name] = Encoding.UTF8.GetString(file.Content);
        }

        var result = reader.Read(new InfraSpineInput(dotText, hclFiles), tenantId, scanJobId);

        if (result.UsedHclFallback)
        {
            logger.LogWarning(
                "Infra spine for scan job {ScanJobId} was built from the HCL fallback, not the " +
                "Terraform DOT graph", scanJobId);
        }

        var nodeIdByKey = await UpsertNodesAsync(result.Nodes, scanJobId, ct);
        var edgeCount = await UpsertEdgesAsync(result.Edges, nodeIdByKey, tenantId, scanJobId);

        await unitOfWork.CompleteAsync();

        logger.LogInformation(
            "Infra spine for scan job {ScanJobId}: {NodeCount} node(s), {EdgeCount} edge(s)",
            scanJobId, result.Nodes.Count, edgeCount);
    }

    /// <summary>
    /// Adds every candidate node whose (<c>ScanJobId</c>, <c>NodeKey</c>) isn't already taken.
    /// A collision is not an error — it means an earlier write already produced this exact
    /// canonical node for this scan job — so it's logged and the existing row wins rather than
    /// the insert throwing on the unique index.
    /// </summary>
    /// <returns>Every node key for this scan job mapped to its (new or pre-existing) id, so
    /// edges can be built against real ids next.</returns>
    private async Task<Dictionary<string, Guid>> UpsertNodesAsync(
        IReadOnlyList<GraphNode> candidates, Guid scanJobId, CancellationToken ct)
    {
        var existing = await unitOfWork.Repository<GraphNode>().GetWhereAsync(n => n.ScanJobId == scanJobId);
        var nodeIdByKey = existing.ToDictionary(n => n.NodeKey, n => n.Id, StringComparer.Ordinal);

        foreach (var candidate in candidates)
        {
            if (nodeIdByKey.ContainsKey(candidate.NodeKey))
            {
                logger.LogWarning(
                    "Node key {NodeKey} already exists for scan job {ScanJobId}; keeping the " +
                    "existing row instead of inserting a duplicate (two extractors producing the " +
                    "same canonical id?)",
                    candidate.NodeKey, scanJobId);
                continue;
            }

            await unitOfWork.Repository<GraphNode>().AddAsync(candidate);
            nodeIdByKey[candidate.NodeKey] = candidate.Id;
        }

        return nodeIdByKey;
    }

    private async Task<int> UpsertEdgesAsync(
        IReadOnlyList<InfraSpineEdge> edges, IReadOnlyDictionary<string, Guid> nodeIdByKey,
        Guid tenantId, Guid scanJobId)
    {
        var count = 0;

        foreach (var edge in edges)
        {
            if (!nodeIdByKey.TryGetValue(edge.FromNodeKey, out var fromId) ||
                !nodeIdByKey.TryGetValue(edge.ToNodeKey, out var toId))
            {
                // The reader only ever emits edges between nodes it also emitted, so this
                // shouldn't happen — logged rather than thrown, since a dangling edge
                // reference is a reason to drop that one edge, not to fail the whole write.
                logger.LogWarning(
                    "Skipping infra-spine edge {From} -> {To} for scan job {ScanJobId}: an " +
                    "endpoint did not resolve to a persisted node",
                    edge.FromNodeKey, edge.ToNodeKey, scanJobId);
                continue;
            }

            await unitOfWork.Repository<GraphEdge>().AddAsync(new GraphEdge
            {
                Id = Guid.CreateVersion7(),
                TenantId = tenantId,
                ScanJobId = scanJobId,
                FromNodeId = fromId,
                ToNodeId = toId,
                Relation = edge.Relation,
                Seam = Seam.InfraSpine,
                Confidence = Confidence.Certain,
                OrientedAttackDir = edge.OrientedAttackDir,
            });
            count++;
        }

        return count;
    }
}

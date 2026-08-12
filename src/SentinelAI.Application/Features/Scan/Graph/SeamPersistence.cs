using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Graph;

/// <summary>
/// The (scan_job_id, node_key) upsert-on-collision and node-key-to-database-id resolution
/// pattern <c>InfraSpineWriter</c> (SEC-17) established, shared by the three SEC-18/19 seam
/// writers below rather than copy-pasted three times. <c>InfraSpineWriter</c> itself is
/// untouched — SEC-17's own code is frozen for this ticket — so this is a new, independent
/// implementation of that pattern, not an extraction from it.
/// </summary>
internal static class SeamPersistence
{
    /// <summary>
    /// Adds every candidate node whose (<c>ScanJobId</c>, <c>NodeKey</c>) isn't already taken —
    /// by an earlier write in this same call, by another seam writer, or by the infra spine
    /// itself. A collision is not an error: it means this exact canonical node already exists
    /// for this scan job, so the existing row wins and a warning is logged rather than the
    /// insert violating the unique index.
    /// </summary>
    /// <returns>Every node key for this scan job mapped to its (new or pre-existing) id, so
    /// edges can be built against real ids next.</returns>
    public static async Task<Dictionary<string, Guid>> UpsertNodesAsync(
        IUnitOfWork unitOfWork, IReadOnlyList<GraphNode> candidates, Guid scanJobId, ILogger logger)
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

    /// <summary>
    /// Resolves one node-key-addressed edge to real database ids and adds it, or skips it with a
    /// warning if either endpoint never resolved to a persisted node — the same degrade-not-crash
    /// behavior <c>InfraSpineWriter</c> uses, since a reader only ever emits edges between nodes
    /// it also emitted, so a dangling reference here is a reason to drop that one edge, not to
    /// fail the whole write.
    /// </summary>
    /// <returns>1 if the edge was added, 0 if it was skipped — summed by the caller for logging.</returns>
    public static async Task<int> UpsertEdgeAsync(
        IUnitOfWork unitOfWork, IReadOnlyDictionary<string, Guid> nodeIdByKey,
        Guid tenantId, Guid scanJobId, string fromNodeKey, string toNodeKey, string relation,
        Seam seam, Confidence confidence, bool orientedAttackDir, ILogger logger)
    {
        if (!nodeIdByKey.TryGetValue(fromNodeKey, out var fromId) || !nodeIdByKey.TryGetValue(toNodeKey, out var toId))
        {
            logger.LogWarning(
                "Skipping {Seam} edge {From} -> {To} for scan job {ScanJobId}: an endpoint did " +
                "not resolve to a persisted node",
                seam, fromNodeKey, toNodeKey, scanJobId);
            return 0;
        }

        await unitOfWork.Repository<GraphEdge>().AddAsync(new GraphEdge
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            ScanJobId = scanJobId,
            FromNodeId = fromId,
            ToNodeId = toId,
            Relation = relation,
            Seam = seam,
            Confidence = confidence,
            OrientedAttackDir = orientedAttackDir,
        });

        return 1;
    }
}

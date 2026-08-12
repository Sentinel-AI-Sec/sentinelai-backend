using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;

namespace SentinelAI.Application.Features.Scan.Graph;

/// <summary>
/// SEC-19: persists the code→infra seam — a <c>Code</c> node, an <c>Image</c> node, and a
/// <c>runs-as</c> edge between them scored <c>Inferred</c> or <c>Unresolved</c> per
/// <see cref="ICodeInfraSeamReader"/>'s own doc remarks — as <see cref="Models.GraphNode"/>/
/// <see cref="Models.GraphEdge"/> rows. Unlike <see cref="DepCodeSeamWriter"/> and
/// <see cref="RoleResourceSeamWriter"/>, confidence here is per-edge, not a fixed
/// <c>Confidence.Certain</c> the writer stamps uniformly — this seam is a best-effort name match,
/// not an explicit reference, so it carries the reader's own verdict through unchanged.
/// </summary>
/// <remarks>
/// Standalone and not wired to any bundle-store read or scan-job pipeline — same reasoning as
/// <see cref="DepCodeSeamWriter"/>'s remarks.
/// </remarks>
public sealed class CodeInfraSeamWriter(
    ICodeInfraSeamReader reader, IUnitOfWork unitOfWork, ILogger<CodeInfraSeamWriter> logger)
{
    public async Task WriteAsync(
        string projectFilePath, string dockerfileText, IReadOnlyDictionary<string, string> hclFiles,
        Guid tenantId, Guid scanJobId, CancellationToken ct)
    {
        var result = reader.Read(new CodeInfraSeamInput(projectFilePath, dockerfileText, hclFiles), tenantId, scanJobId);

        var nodeIdByKey = await SeamPersistence.UpsertNodesAsync(unitOfWork, result.Nodes, scanJobId, logger);

        var edgeCount = 0;
        foreach (var edge in result.Edges)
        {
            // Already attack-oriented by construction — runs-as points code -> the image it is
            // deployed as, which is the direction a compromise of that code would move.
            edgeCount += await SeamPersistence.UpsertEdgeAsync(
                unitOfWork, nodeIdByKey, tenantId, scanJobId, edge.FromNodeKey, edge.ToNodeKey, edge.Relation,
                Seam.CodeInfra, edge.Confidence, orientedAttackDir: true, logger);
        }

        await unitOfWork.CompleteAsync();

        logger.LogInformation(
            "Code-infra seam for scan job {ScanJobId}: {NodeCount} node(s), {EdgeCount} edge(s)",
            scanJobId, result.Nodes.Count, edgeCount);
    }
}

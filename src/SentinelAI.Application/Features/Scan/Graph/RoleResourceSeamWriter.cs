using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;

namespace SentinelAI.Application.Features.Scan.Graph;

/// <summary>
/// SEC-18 part B: persists the role→resource seam — a <c>can-access</c> edge from an
/// <c>IamRole</c> node to every <c>Resource</c> node its Terraform IAM policies grant access to
/// (inline, standalone, and managed-attachment forms alike, including wildcard grants widened
/// rather than dropped) — as <see cref="Models.GraphNode"/>/<see cref="Models.GraphEdge"/> rows,
/// all stamped <c>Seam.RoleResource</c>/<c>Confidence.Certain</c> (an IAM policy statement is an
/// explicit grant, not a heuristic — the fragile, heuristic seam in this pair of tickets is
/// SEC-19's <c>CodeInfraSeamWriter</c>, not this one).
/// </summary>
/// <remarks>
/// Standalone and not wired to any bundle-store read or scan-job pipeline — same reasoning as
/// <see cref="DepCodeSeamWriter"/>'s remarks. The caller supplies the already-read <c>.tf</c>
/// file contents directly (the same shape <c>InfraSpineWriter</c> reads via
/// <c>IBundleStore.OpenGraphInputsAsync</c>, so a future call site can hand this writer the same
/// dictionary it hands that one).
/// </remarks>
public sealed class RoleResourceSeamWriter(
    IRoleResourceSeamReader reader, IUnitOfWork unitOfWork, ILogger<RoleResourceSeamWriter> logger)
{
    public async Task WriteAsync(
        IReadOnlyDictionary<string, string> hclFiles, Guid tenantId, Guid scanJobId, CancellationToken ct)
    {
        var result = reader.Read(new RoleResourceSeamInput(hclFiles), tenantId, scanJobId);

        var nodeIdByKey = await SeamPersistence.UpsertNodesAsync(unitOfWork, result.Nodes, scanJobId, logger);

        var edgeCount = 0;
        foreach (var edge in result.Edges)
        {
            // Already attack-oriented by construction — can-access already points role -> what
            // the attacker who holds that role can reach — so no separate reversal step applies
            // here the way it does for the infra spine's Terraform build-order edges.
            edgeCount += await SeamPersistence.UpsertEdgeAsync(
                unitOfWork, nodeIdByKey, tenantId, scanJobId, edge.FromNodeKey, edge.ToNodeKey, edge.Relation,
                Seam.RoleResource, Confidence.Certain, orientedAttackDir: true, logger);
        }

        await unitOfWork.CompleteAsync();

        logger.LogInformation(
            "Role-resource seam for scan job {ScanJobId}: {NodeCount} node(s), {EdgeCount} edge(s), " +
            "{WidenedCount} from wildcard widening",
            scanJobId, result.Nodes.Count, edgeCount, result.Edges.Count(e => e.Widened));
    }
}

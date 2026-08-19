using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;

namespace SentinelAI.Application.Features.Scan.Graph;

/// <summary>
/// SEC-18 part A: persists the dep→code seam — every package in a project's lock file, plus
/// its <c>used-by</c> edge to that project's <c>Code</c> node — as <see cref="Models.GraphNode"/>/
/// <see cref="Models.GraphEdge"/> rows, all stamped <c>Seam.DepCode</c>/<c>Confidence.Certain</c>
/// (a lock file is a resolved, explicit dependency graph, not a heuristic).
/// </summary>
/// <remarks>
/// Standalone and not wired to any bundle-store read or scan-job pipeline, by design — see this
/// project's SEC-18/19 task brief: no scan-job orchestration story exists yet anywhere in this
/// codebase, including for SEC-16's own <c>GraphSeeder</c> or SEC-17's own <c>InfraSpineWriter</c>.
/// The caller supplies the lock file's path and content directly, already read out of wherever
/// they came from; wiring an <c>IBundleStore</c> read (there is no established bundle-path
/// convention yet for a per-project <c>packages.lock.json</c>, unlike <c>graph-inputs/</c> for
/// SEC-17) is a future concern, likely alongside SEC-46.
/// </remarks>
public sealed class DepCodeSeamWriter(
    IDepCodeSeamReader reader, IUnitOfWork unitOfWork, ILogger<DepCodeSeamWriter> logger)
{
    public async Task WriteAsync(
        string projectFilePath, string lockFileJson, Guid tenantId, Guid scanJobId, CancellationToken ct)
    {
        var result = reader.Read(new DepCodeSeamInput(projectFilePath, lockFileJson), tenantId, scanJobId);

        var nodeIdByKey = await SeamPersistence.UpsertNodesAsync(unitOfWork, result.Nodes, scanJobId, logger);

        var edgeCount = 0;
        foreach (var edge in result.Edges)
        {
            // Already attack-oriented by construction — a compromised package is the attacker's
            // entry point into the code that depends on it — so unlike the infra spine there is
            // no separate reversal step to prove ran.
            edgeCount += await SeamPersistence.UpsertEdgeAsync(
                unitOfWork, nodeIdByKey, tenantId, scanJobId, edge.FromNodeKey, edge.ToNodeKey, edge.Relation,
                Seam.DepCode, Confidence.Certain, orientedAttackDir: true, logger);
        }

        await unitOfWork.CompleteAsync();

        logger.LogInformation(
            "Dep-code seam for scan job {ScanJobId}: {NodeCount} node(s), {EdgeCount} edge(s)",
            scanJobId, result.Nodes.Count, edgeCount);
    }
}

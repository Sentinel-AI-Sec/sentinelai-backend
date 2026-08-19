using System.Text;
using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Graph;

/// <summary>
/// SEC-20's persistence half: decorates the stored resource graph with this scan's findings,
/// traverses it into bounded candidate chains, and writes them as <c>chains</c>/<c>chain_hops</c>
/// rows.
/// </summary>
/// <remarks>
/// <para>
/// Same split as every seam in this feature — <see cref="GraphDecorator"/> and
/// <see cref="ExploitChainTraverser"/> are pure and fully unit-testable, and this class owns
/// the parts that need a database and a bundle: reading the graph back, resolving infra
/// findings against the Terraform source, marking hot nodes, and writing the chains.
/// </para>
/// <para>
/// Findings arrive as a parameter rather than being read back from <c>findings</c>, exactly as
/// <see cref="ThinSlice.ThinSlicePipeline"/> takes them: normalization (SEC-14/15/16) is the
/// stage that produces them, and the in-memory list is the richer one —
/// <see cref="Finding.Location"/> is mapped out of the table by design, and this class needs it
/// to place an infra finding on a Terraform resource. The rows themselves must exist by the time
/// this runs, though, because a hop's <c>finding_id</c> is a foreign key;
/// <see cref="Normalization.NormalizedFindingWriter"/> writes them and the stage pipeline calls
/// it first.
/// </para>
/// <para>
/// <see cref="GraphStagePipeline"/> is what calls this in a real scan, behind
/// <c>POST /v1/scans/{id}/graph</c>. There is still no automatic orchestration — the trigger is
/// manual (see <c>docs/Walking_Skeleton.md</c> §6).
/// </para>
/// </remarks>
public sealed class CandidateChainWriter(
    IBundleStore bundleStore,
    IInfraFindingLocator infraFindingLocator,
    GraphDecorator decorator,
    ExploitChainTraverser traverser,
    IUnitOfWork unitOfWork,
    ILogger<CandidateChainWriter> logger)
{
    /// <summary>
    /// Generates and persists the candidate chains for one scan job, and returns them for the
    /// stage that consumes them next (SEC-21's query construction and attack-graph handoff).
    /// </summary>
    public async Task<IReadOnlyList<CandidateChain>> WriteAsync(
        string bundleLocator, IReadOnlyList<Finding> findings, Guid tenantId, Guid scanJobId, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var nodes = (await unitOfWork.Repository<GraphNode>().GetWhereAsync(n => n.ScanJobId == scanJobId)).ToList();
        var edges = (await unitOfWork.Repository<GraphEdge>().GetWhereAsync(e => e.ScanJobId == scanJobId)).ToList();

        if (nodes.Count == 0)
        {
            logger.LogWarning(
                "No graph nodes stored for scan job {ScanJobId}; the seam writers have not run, so "
                + "there is nothing to traverse", scanJobId);
            return [];
        }

        var decoration = decorator.Decorate(nodes, findings, await LocateInfraFindingsAsync(bundleLocator, findings, ct));

        // The nodes came back tracked, so the IsHot flags the decorator set would flush on their
        // own; marking them explicitly says so at the call site instead of leaving a persisted
        // change to a property of how they were queried.
        foreach (var node in nodes.Where(n => n.IsHot))
            await unitOfWork.Repository<GraphNode>().UpdateAsync(node);

        var candidates = traverser.Traverse(nodes, edges, decoration);

        foreach (var candidate in candidates)
            await PersistAsync(candidate, tenantId, scanJobId);

        await unitOfWork.CompleteAsync();

        logger.LogInformation(
            "Candidate chains for scan job {ScanJobId}: {ChainCount} chain(s) from {NodeCount} node(s) "
            + "and {EdgeCount} edge(s){Detail}",
            scanJobId, candidates.Count, nodes.Count, edges.Count, Summarize(candidates));

        return candidates;
    }

    /// <summary>
    /// Resolves this scan's infra findings against the bundle's Terraform source.
    /// </summary>
    /// <remarks>
    /// A bundle with no graph inputs is not an error — the runner may have skipped
    /// <c>terraform</c> entirely — it just means infra findings stay file-grained and cannot
    /// decorate an infra node. Degrading to an empty map keeps the code and dependency layers
    /// working rather than failing the whole stage.
    /// </remarks>
    private async Task<IReadOnlyDictionary<string, string>> LocateInfraFindingsAsync(
        string bundleLocator, IReadOnlyList<Finding> findings, CancellationToken ct)
    {
        var locations = findings
            .Where(f => f.Layer == Layer.Infra && !string.IsNullOrWhiteSpace(f.Location))
            .Select(f => f.Location!)
            .ToList();

        if (locations.Count == 0) return new Dictionary<string, string>(StringComparer.Ordinal);

        var hclFiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in await bundleStore.OpenGraphInputsAsync(bundleLocator, ct))
        {
            if (file.Name.EndsWith(".tf", StringComparison.OrdinalIgnoreCase))
                hclFiles[file.Name] = Encoding.UTF8.GetString(file.Content);
        }

        var resolved = infraFindingLocator.Locate(hclFiles, locations);

        logger.LogInformation(
            "Placed {Resolved} of {Total} distinct infra finding location(s) onto a Terraform resource",
            resolved.Count, locations.Distinct(StringComparer.Ordinal).Count());

        return resolved;
    }

    /// <summary>
    /// Writes one candidate as a <see cref="Chain"/> and its <see cref="ChainHop"/> rows.
    /// </summary>
    /// <remarks>
    /// <see cref="ChainStatus.Candidate"/> and nothing else: this stage found a path, it did not
    /// assert one. Promotion to <c>Asserted</c>/<c>Validated</c> belongs to Red and Blue.
    /// <para>
    /// The hop rows deliberately store less than the in-memory candidate does. A hop's node is
    /// recoverable from its edge (<c>chain_hops</c> has no node column in the D2 schema, and
    /// adding one would duplicate a join that <c>graph_edges</c> already holds), and the seed
    /// node is the first edge's <c>from_node_id</c>.
    /// </para>
    /// </remarks>
    private async Task PersistAsync(CandidateChain candidate, Guid tenantId, Guid scanJobId)
    {
        var chain = new Chain
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            ScanJobId = scanJobId,
            HopCount = candidate.HopCount,
            Priority = candidate.Priority,
            Status = ChainStatus.Candidate,

            // Computed by the traverser with ConfidenceExtensions.Weakest over the path's edges,
            // never assigned from a hop or a guess (Data_Contracts.md §3).
            MinConfidence = candidate.MinConfidence,
        };

        await unitOfWork.Repository<Chain>().AddAsync(chain);

        foreach (var hop in candidate.Hops)
        {
            await unitOfWork.Repository<ChainHop>().AddAsync(new ChainHop
            {
                Id = Guid.CreateVersion7(),
                TenantId = tenantId,
                ChainId = chain.Id,
                HopOrder = hop.Order,

                // Null on the seed hop, which arrived from nowhere.
                EdgeId = hop.EdgeFromPrevious?.Id,

                // The most severe finding on this node, or null when nothing was reported there.
                // The decorator already ordered them, so this is a take, not a re-sort.
                FindingId = hop.Findings.Count > 0 ? hop.Findings[0].Id : null,

                // Empty slots. Red fills the technique and Blue the verdict, both by way of
                // ChainOutcomeWriter reading the debate transcript — none of which has run at
                // this stage.
                //
                // Unassessed, emphatically not "not validated" (audit 42-A). This row is minutes
                // old and no agent has seen it; a false in a blue_validated column said the same
                // word here as it did for a hop Blue had examined and rejected, and the dashboard
                // reported the difference as no difference. HopVerdict keeps the two apart, and
                // this is the "nobody has looked yet" end of it.
                TechniqueId = string.Empty,
                BlueVerdict = HopVerdict.Unassessed,
            });
        }
    }

    /// <summary>The strongest candidate, for the log line — the one a reader wants to see named.</summary>
    private static string Summarize(IReadOnlyList<CandidateChain> candidates)
    {
        if (candidates.Count == 0) return string.Empty;

        var best = candidates[0];
        var path = string.Join(" -> ", best.Hops.Select(h => h.Node.NodeKey));

        return $"; top candidate ({best.MinConfidence}, {best.HopCount} hop(s)): {path}";
    }
}

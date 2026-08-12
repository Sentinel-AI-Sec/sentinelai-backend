using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Abstractions;

/// <summary>
/// Turns a bundle's Terraform graph inputs into the infra layer of the resource graph
/// (SEC-17). One implementation, resolved directly rather than as an
/// <c>IEnumerable&lt;T&gt;</c> like <see cref="IFindingExtractor"/> — there is exactly one
/// source of infra-spine nodes, not one per tool.
/// </summary>
public interface IInfraSpineReader
{
    /// <summary>
    /// Reads the graph inputs for one scan job and returns its nodes, already canonical
    /// (<see cref="ValueObjects.NodeId"/>-built, tagged with <paramref name="tenantId"/> and
    /// <paramref name="scanJobId"/>), plus the edges between them, still keyed by node key
    /// rather than by database id — the caller has not persisted the nodes yet, so there is
    /// no id to reference.
    /// </summary>
    InfraSpineReadResult Read(InfraSpineInput input, Guid tenantId, Guid scanJobId);
}

/// <summary>
/// The graph-inputs files pulled out of a bundle, undecoded from what
/// <c>IBundleStore.OpenGraphInputsAsync</c> returned. <see cref="DotText"/> is null when no
/// <c>terraform-graph.dot</c> was in the bundle at all (as opposed to present but empty).
/// </summary>
/// <param name="HclFiles">Bundle-root-relative filename (e.g. <c>graph-inputs/infra/iam.tf</c>) to
/// its decoded text content. Only <c>.tf</c> files matter to this reader.</param>
public sealed record InfraSpineInput(string? DotText, IReadOnlyDictionary<string, string> HclFiles);

/// <summary>
/// One infra-spine edge, still keyed by <see cref="GraphNode.NodeKey"/> rather than by
/// <see cref="GraphNode.Id"/>. Every edge this reader produces has already been re-oriented to
/// attack direction (Terraform's build-order direction reversed) — <see cref="FromNodeKey"/> is
/// where an attacker starts, <see cref="ToNodeKey"/> is where the edge lets them move to.
/// </summary>
public sealed record InfraSpineEdge(string FromNodeKey, string ToNodeKey, string Relation, bool OrientedAttackDir);

/// <summary>The result of one <see cref="IInfraSpineReader.Read"/> call.</summary>
/// <param name="UsedHclFallback">True when the DOT input was missing/empty/unusable and the
/// result came from parsing raw <c>.tf</c> source instead (SEC-17 step 4) — surfaced so the
/// caller can log that the degraded path ran.</param>
public sealed record InfraSpineReadResult(
    IReadOnlyList<GraphNode> Nodes, IReadOnlyList<InfraSpineEdge> Edges, bool UsedHclFallback);

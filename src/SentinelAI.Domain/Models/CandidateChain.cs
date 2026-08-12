using SentinelAI.Domain.Enums;

namespace SentinelAI.Domain.Models;

/// <summary>
/// One deterministically-generated candidate exploit path (SEC-20): an ordered walk over real
/// graph edges, with the technique and evidence slots left empty for the Red agent to fill.
/// </summary>
/// <remarks>
/// <para>
/// This is the in-memory handoff shape, not the persisted one. <see cref="Chain"/>/
/// <see cref="ChainHop"/> are the database rows; this record is what the traverser produces and
/// what the retrieval and debate stages consume (SEC-21). Keeping them separate is what lets a
/// candidate carry the whole <see cref="GraphNode"/> and its findings — which the debate needs
/// to reason and which <c>chain_hops</c> deliberately does not store, since the same facts are
/// already rows in <c>graph_nodes</c> and <c>findings</c>.
/// </para>
/// <para>
/// <b>Candidate, not claim.</b> Everything here is derived from edges an extractor actually
/// emitted. Nothing in this record asserts that the path is exploitable — that is what the
/// debate is for, and it is why <see cref="ChainStatus.Candidate"/> is the only status a
/// freshly-traversed chain may carry.
/// </para>
/// </remarks>
/// <param name="Hops">The path, seed first. Always at least two hops: a single node is not a
/// path, and a candidate has to cross at least two layers to be worth handing over.</param>
/// <param name="MinConfidence">The weakest edge anywhere in the path, per AID-01 §3.3. Computed
/// by the traverser with <see cref="ConfidenceExtensions.Weakest{T}"/>, never assigned.</param>
/// <param name="Priority">Rank among the candidates from one traversal, 1 = first. See
/// <c>ExploitChainTraverser</c> for the ordering and why it is deterministic.</param>
public sealed record CandidateChain(
    IReadOnlyList<CandidateHop> Hops,
    Confidence MinConfidence,
    int Priority)
{
    /// <summary>
    /// Hops in the AID-01 §3.2 sense — edges traversed, which is one fewer than the number of
    /// nodes on the path. The 3–4 hop cap is expressed in these units, so a 4-hop candidate
    /// visits five nodes.
    /// </summary>
    public int HopCount => Hops.Count - 1;

    /// <summary>The node the walk started from — a hot node, by construction.</summary>
    public CandidateHop Seed => Hops[0];

    /// <summary>The node the walk ended at. The crown jewel, when the path reached one.</summary>
    public CandidateHop Target => Hops[^1];

    /// <summary>
    /// The distinct layers this path crosses. A candidate that stays inside one layer is not a
    /// cross-layer chain and the traverser does not emit it.
    /// </summary>
    public IReadOnlyCollection<Layer> Layers => [.. Hops.Select(h => h.Node.Layer).Distinct()];

    /// <summary>The severity of the most severe finding decorating any node on the path.</summary>
    public int MaxSeverity => Hops.Max(h => h.MaxSeverity);
}

/// <summary>
/// One position on a candidate path: the node reached, the edge that reached it, and the
/// findings decorating it.
/// </summary>
/// <param name="Order">Zero-based position, so it matches <see cref="ChainHop.HopOrder"/>.</param>
/// <param name="Node">The node at this position.</param>
/// <param name="EdgeFromPrevious">The edge traversed to arrive here — null on the seed hop only,
/// which nothing arrived at. This mirrors <c>chain_hops.edge_id</c> being nullable "first hop may
/// be a seed node" in the D2 schema.</param>
/// <param name="Findings">Every finding decorating this node, most severe first. Empty is normal
/// and not a defect: an image or a task definition is a real place on a real path whether or not
/// a scanner happened to report on it, and dropping such hops would break the chain rather than
/// describe it.</param>
public sealed record CandidateHop(
    int Order,
    GraphNode Node,
    GraphEdge? EdgeFromPrevious,
    IReadOnlyList<Finding> Findings)
{
    /// <summary>The tactic this hop occupies, from its node type.</summary>
    public AttackTactic Tactic => Node.NodeType.Tactic();

    /// <summary>Severity of this hop's most severe finding, or -1 when nothing decorates it.</summary>
    public int MaxSeverity => Findings.Count == 0 ? -1 : Findings.Max(f => f.Severity);

    /// <summary>
    /// The ATT&amp;CK technique the Red agent asserts for this hop. <b>An empty slot on a
    /// candidate</b> — the traverser knows the path is walkable, not what technique walks it,
    /// and inventing one here would put a graph-stage guess where a cited agent claim belongs.
    /// </summary>
    public string TechniqueId { get; init; } = string.Empty;

    /// <summary>
    /// Evidence backing this hop. Empty on a candidate, for the same reason as
    /// <see cref="TechniqueId"/>: evidence comes from retrieval and the debate transcript,
    /// which have not run yet.
    /// </summary>
    public IReadOnlyList<string> Evidence { get; init; } = [];
}

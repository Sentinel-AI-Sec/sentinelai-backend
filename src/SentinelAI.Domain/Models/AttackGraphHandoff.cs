using SentinelAI.Domain.Enums;

namespace SentinelAI.Domain.Models;

/// <summary>
/// SEC-21: what the graph stage hands the debate — the ordered candidate paths for one scan, and
/// nothing asserted about them.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two graphs, and only one direction between them.</b> The resource graph is static: nodes and
/// edges an extractor read out of Terraform, a lock file or a Dockerfile, true whether or not
/// anyone ever attacks anything. The attack graph is asserted: techniques a Red agent claims and
/// evidence it cites, which a Blue agent then attacks. This object is the boundary between the
/// two and crosses it once, outward. <see cref="From"/> refuses a candidate that already carries a
/// technique or evidence, because a candidate that arrives pre-asserted is a graph-stage guess
/// wearing a cited claim's clothes — and by the time it reaches a report there is nothing left in
/// the data that tells the two apart. AID-01 §7 makes that distinction the product's central
/// promise, so it is enforced here rather than described.
/// </para>
/// <para>
/// It adds no field <see cref="CandidateChain"/> does not already have. A chain already carries
/// its hops, their nodes, the findings decorating them and the weakest-link confidence of the
/// whole path; what this adds is the scan those chains belong to, a guaranteed order, and the
/// tenant check below. Re-modelling a chain here would give the debate a second shape for the
/// same facts, which is exactly how two shapes drift apart.
/// </para>
/// <para>
/// <b>Not the persisted form.</b> <c>CandidateChainWriter</c> already writes these paths as
/// <c>chains</c>/<c>chain_hops</c> rows with <see cref="ChainStatus.Candidate"/>. This is the
/// in-memory handoff for one run, and it is deliberately cheap to build so that a caller with the
/// traverser's output never has to go back to the database to hand it on.
/// </para>
/// </remarks>
/// <param name="Candidates">The paths, priority 1 first. Empty is a real answer and not a
/// failure: a graph with no edges — the walking skeleton's, or a bundle that carried no Terraform
/// and no lock file — has no path to offer, and saying so is more useful than an absent handoff a
/// caller has to null-check.</param>
public sealed record AttackGraphHandoff(
    Guid TenantId,
    Guid ScanJobId,
    IReadOnlyList<CandidateChain> Candidates)
{
    /// <summary>
    /// Builds the handoff from one traversal's output, ordered and checked.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Candidates are sorted by <see cref="CandidateChain.Priority"/> rather than being required
    /// to arrive sorted, because the ranking that produced those numbers lives in the traverser
    /// and a caller that filtered the list — took the top few, dropped the ones whose seed was
    /// already reported — must not have to preserve it by hand. Priorities are left as they are:
    /// they identify the chain in the traverser's full ranking, and renumbering a filtered subset
    /// 1..n would quietly claim a chain was ranked higher than it was.
    /// </para>
    /// <para>
    /// The tenant and scan-job check is not ceremony. Every node and finding on a hop is a row
    /// that was read from the database by some other component, and a handoff assembled from two
    /// scans' worth of them puts one customer's resources into another customer's prompt. That is
    /// the one defect here that cannot be walked back after the fact, so it fails loudly at the
    /// boundary instead of being trusted upstream.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">A candidate already carries an asserted
    /// technique or evidence, or one of its hops belongs to a different tenant or scan job.</exception>
    public static AttackGraphHandoff From(
        Guid tenantId, Guid scanJobId, IReadOnlyList<CandidateChain> candidates)
    {
        ArgumentNullException.ThrowIfNull(candidates);

        foreach (var hop in candidates.SelectMany(c => c.Hops))
        {
            if (hop.TechniqueId.Length > 0 || hop.Evidence.Count > 0)
            {
                throw new InvalidOperationException(
                    $"Hop {hop.Order} on {hop.Node.NodeKey} already carries an asserted technique "
                    + "or evidence. The technique and evidence slots on a candidate belong to the "
                    + "debate; filling them before the handoff makes a graph-stage guess "
                    + "indistinguishable from a cited claim.");
            }

            if (hop.Node.TenantId != tenantId || hop.Node.ScanJobId != scanJobId)
            {
                throw new InvalidOperationException(
                    $"Node {hop.Node.NodeKey} belongs to tenant {hop.Node.TenantId} / scan job "
                    + $"{hop.Node.ScanJobId}, not to {tenantId} / {scanJobId}. A handoff assembled "
                    + "across scans would put one tenant's resources into another's prompt.");
            }
        }

        return new AttackGraphHandoff(
            tenantId, scanJobId, [.. candidates.OrderBy(c => c.Priority)]);
    }

    /// <summary>True when the traversal found no path worth handing over.</summary>
    public bool IsEmpty => Candidates.Count == 0;

    /// <summary>
    /// Every node any candidate visits, without repeats, in the order the paths visit them.
    /// </summary>
    /// <remarks>
    /// First appearance wins, so the highest-priority path's seed leads. A node reached by two
    /// chains appears once: it is one resource, and listing it twice would read to an agent as two.
    /// </remarks>
    public IReadOnlyList<GraphNode> Nodes =>
        [.. Candidates.SelectMany(c => c.Hops).Select(h => h.Node).DistinctBy(n => n.NodeKey, StringComparer.Ordinal)];

    /// <summary>
    /// Every finding decorating any hop on any candidate, without repeats, most severe first.
    /// </summary>
    /// <remarks>
    /// These are the findings that are actually on an attack path, which is a strictly smaller set
    /// than the scan's findings and the one worth spending retrieval and prompt budget on.
    /// De-duplicated because one finding decorates one node, and that node can sit on several
    /// chains — by object identity rather than by <see cref="Finding.Id"/>, which is the same
    /// answer for anything the graph stage produced and cannot collapse two findings that have not
    /// been given ids yet.
    /// </remarks>
    public IReadOnlyList<Finding> Findings =>
        [.. Candidates
            .SelectMany(c => c.Hops)
            .SelectMany(h => h.Findings)
            .Distinct()
            .OrderByDescending(f => f.Severity)];

    /// <summary>
    /// The weakest join anywhere in this handoff — the confidence the whole set inherits under
    /// AID-01 §3.3.
    /// </summary>
    /// <remarks>
    /// <see cref="Confidence.Certain"/> when <see cref="IsEmpty"/>, following
    /// <see cref="ConfidenceExtensions.Weakest{T}"/>: with nothing asserted there is nothing to
    /// doubt. Read it together with <see cref="IsEmpty"/> — on its own it would look like a strong
    /// answer rather than an absent one.
    /// </remarks>
    public Confidence WeakestConfidence => Candidates.Weakest(c => c.MinConfidence);
}

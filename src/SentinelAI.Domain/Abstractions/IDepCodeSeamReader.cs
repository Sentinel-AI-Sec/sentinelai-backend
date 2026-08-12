using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Abstractions;

/// <summary>
/// Turns a project's NuGet lock file into the dep→code seam of the resource graph (SEC-18 part
/// A): a <c>Pkg</c> node per package (direct and transitive) plus a <c>used-by</c> edge from
/// each package to the <c>Code</c> node that consumes it. One implementation, resolved directly
/// rather than as an <c>IEnumerable&lt;T&gt;</c> — there is exactly one lock-file format this
/// reads (NuGet's <c>packages.lock.json</c>), same reasoning as <see cref="IInfraSpineReader"/>.
/// </summary>
public interface IDepCodeSeamReader
{
    /// <summary>
    /// Reads one project's lock file and returns its package nodes, the project's own Code
    /// node, and the edges between them — already canonical and tagged with
    /// <paramref name="tenantId"/>/<paramref name="scanJobId"/>, still keyed by node key rather
    /// than by database id (the caller has not persisted anything yet).
    /// </summary>
    DepCodeSeamReadResult Read(DepCodeSeamInput input, Guid tenantId, Guid scanJobId);
}

/// <summary>
/// One project's dep→code seam input.
/// </summary>
/// <param name="ProjectFilePath">
/// Bundle-relative path to the lock file itself, e.g. <c>src/OrderService/packages.lock.json</c>.
/// Used only to derive the project's provisional Code node — see
/// <c>ProvisionalCodeNodeResolver</c> for why this is a stand-in rather than a formal source of
/// Code-node identity.
/// </param>
/// <param name="LockFileJson">The raw <c>packages.lock.json</c> content.</param>
public sealed record DepCodeSeamInput(string ProjectFilePath, string LockFileJson);

/// <summary>
/// One dep→code edge. Always <c>used-by</c>, always certain — a lock file is an explicit,
/// resolved dependency graph, not a heuristic — so unlike <see cref="CodeInfraSeamEdge"/> there
/// is no per-edge confidence to carry; the writer stamps <c>Confidence.Certain</c> for all of
/// these, the same way <see cref="InfraSpineEdge"/> does for infra-spine edges.
/// </summary>
public sealed record DepCodeSeamEdge(string FromNodeKey, string ToNodeKey, string Relation);

/// <summary>The result of one <see cref="IDepCodeSeamReader.Read"/> call.</summary>
/// <param name="Nodes">Every <c>Pkg</c> node found, plus the project's own <c>Code</c> node.</param>
public sealed record DepCodeSeamReadResult(IReadOnlyList<GraphNode> Nodes, IReadOnlyList<DepCodeSeamEdge> Edges);

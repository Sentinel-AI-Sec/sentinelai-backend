using SentinelAI.Domain.Enums;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// Derives the <c>Code</c> node a dep→code (SEC-18 part A) or code→infra (SEC-19) edge attaches
/// to.
/// </summary>
/// <remarks>
/// <b>No ticket formally owns Code-node creation.</b> <c>GraphSeeder</c> (SEC-45/SEC-16) only
/// ever builds a <c>Code</c> node from an already-canonical <see cref="Models.Finding.NodeRef"/>
/// a Roslyn-family extractor produced (file-path-grained, e.g. <c>code:src/orderservice/order.cs</c>
/// — see <c>FindingUnifier.BuildNodeRef</c>); nothing before SEC-18/19 ever needed to invent a
/// Code node from scratch given only a project's build files. Since this ticket is the first to
/// need one, and neither ticket owns "what is a Code node" as a formal decision, this class picks
/// the narrowest thing that is still correct and documents the choice here rather than silently
/// baking it into two call sites:
/// <list type="bullet">
/// <item>The Code node's identifier is the name of the directory directly containing the
/// project's dependency-manifest or Dockerfile (<c>src/OrderService/packages.lock.json</c> →
/// <c>OrderService</c>), matching this project's own fixture convention — see
/// <c>docs/Walking_Skeleton.md</c>'s <c>code:orderservice</c> example — on the assumption that a
/// <c>packages.lock.json</c>/<c>Dockerfile</c> lives at a project's root, one per project.</item>
/// <item>This is provisional on purpose. It does not read the <c>.csproj</c>'s actual
/// <c>AssemblyName</c>/<c>RootNamespace</c>, so a project whose directory name and assembly name
/// differ produces a Code node that will not line up with a Roslyn finding's file-grained node
/// for that same project — a smaller version of the exact node-granularity gap
/// <c>docs/Walking_Skeleton.md</c> already documents between SEC-16 and SEC-17. Revisit this
/// once a ticket formally owns Code-node identity (project-file parsing, symbol-grained nodes,
/// or whatever that ticket decides).</item>
/// </list>
/// </remarks>
internal static class ProvisionalCodeNodeResolver
{
    /// <summary>
    /// The canonical Code node key for the project that owns <paramref name="projectFilePath"/>
    /// (a <c>packages.lock.json</c> or <c>Dockerfile</c>, bundle-relative).
    /// </summary>
    public static string ResolveNodeKey(string projectFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectFilePath);

        var normalized = projectFilePath.Replace('\\', '/').Trim('/');
        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);

        // No directory component at all (a file at the bundle root) — fall back to the file's
        // own base name rather than throwing, since NodeId itself only rejects a blank
        // identifier, not an unusual one.
        var projectName = segments.Length >= 2
            ? segments[^2]
            : Path.GetFileNameWithoutExtension(normalized);

        return NodeId.For(NodeType.Code, projectName);
    }
}

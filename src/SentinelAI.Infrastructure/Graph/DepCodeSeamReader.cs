using System.Text.Json;
using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-18 part A: builds the dep→code seam — a <c>Pkg</c> node per package in a project's
/// <c>packages.lock.json</c> (direct and transitive alike), a <c>Code</c> node for the project
/// itself (see <see cref="ProvisionalCodeNodeResolver"/> for why that node's identity is
/// provisional), and a <c>used-by</c> edge from each package to that Code node. Every edge this
/// reader produces is <c>Seam.DepCode</c>/<c>Confidence.Certain</c> — a lock file is a resolved,
/// explicit dependency graph, not a heuristic — which is why, unlike <see cref="ICodeInfraSeamReader"/>,
/// the edge DTO carries no per-edge confidence: the writer stamps it uniformly, the same way
/// <c>InfraSpineWriter</c> does for infra-spine edges.
/// </summary>
public sealed class DepCodeSeamReader(ILogger<DepCodeSeamReader> logger) : IDepCodeSeamReader
{
    private const string Relation = "used-by";

    public DepCodeSeamReadResult Read(DepCodeSeamInput input, Guid tenantId, Guid scanJobId)
    {
        var codeNodeKey = ProvisionalCodeNodeResolver.ResolveNodeKey(input.ProjectFilePath);
        NodeId.TryParse(codeNodeKey, out _, out var codeIdentifier);
        var codeNode = GraphNode.Create(tenantId, scanJobId, NodeType.Code, codeIdentifier, Layer.Code);
        codeNode.Id = Guid.CreateVersion7();

        IReadOnlyList<NuGetLockPackage> packages;
        try
        {
            packages = NuGetLockFileParser.Parse(input.LockFileJson);
        }
        catch (JsonException ex)
        {
            // A lock file this reader cannot parse is not a reason to fail the whole seam build
            // — it just means this one project contributes no dep→code edges. Degrading rather
            // than throwing matches TerraformDotParser's treatment of unusable input.
            logger.LogWarning(ex,
                "packages.lock.json for {ProjectFilePath} (scan job {ScanJobId}) could not be parsed; " +
                "no dep-code edges produced for this project",
                input.ProjectFilePath, scanJobId);
            packages = [];
        }

        var nodesByKey = new Dictionary<string, GraphNode>(StringComparer.Ordinal) { [codeNodeKey] = codeNode };
        var edges = new List<DepCodeSeamEdge>();

        foreach (var package in packages)
        {
            if (string.IsNullOrWhiteSpace(package.Name)) continue;

            var pkgNodeKey = NodeId.Package(package.Name);

            if (!nodesByKey.TryGetValue(pkgNodeKey, out var pkgNode))
            {
                pkgNode = GraphNode.Create(tenantId, scanJobId, NodeType.Pkg, package.Name, Layer.Dep);
                pkgNode.Id = Guid.CreateVersion7();
                pkgNode.Attrs = JsonSerializer.Serialize(new { version = package.Version, direct = package.IsDirect });
                nodesByKey[pkgNodeKey] = pkgNode;
            }

            edges.Add(new DepCodeSeamEdge(pkgNodeKey, codeNodeKey, Relation));
        }

        return new DepCodeSeamReadResult([.. nodesByKey.Values], edges);
    }
}

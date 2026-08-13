using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Application.Features.Scan.Graph;

/// <summary>
/// Attaches findings to the structural graph the seam readers built, and marks the nodes a
/// high-severity finding lands on as hot — the seeds SEC-20's traversal starts from.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is not just a dictionary lookup.</b> <c>FindingUnifier.BuildNodeRef</c> keys a
/// finding by the finest subject its scanner reported, which is a file
/// (<c>code:src/orderapp/controllers/orderscontroller.cs</c>) or a package coordinate
/// (<c>pkg:newtonsoft.json:12.0.1</c>). The seam readers key nodes by the structure Terraform
/// and the build files describe (<c>code:orderapp</c>, <c>pkg:newtonsoft.json</c>,
/// <c>iam_role:order_task_role</c>). Both are canonical and neither is wrong; they are simply
/// two granularities for the same things, and until they are joined the graph is two sets of
/// islands — findings with no nodes, nodes with no findings, and therefore zero chains, with
/// nothing erroring. <c>docs/Walking_Skeleton.md</c> records this as the biggest TODO left open
/// by SEC-17 and says it needs an owner before SEC-18/19/20 can be called complete. This class
/// is that owner.
/// </para>
/// <para>
/// <b>It never invents an attachment.</b> Each rule below is a demonstrable identity — the same
/// package, the same project directory, the same Terraform block — not a similarity score. A
/// finding that no rule places stays unattached and is counted, because a finding attached to
/// the wrong node seeds candidate chains that describe an attack on something that was never
/// reported.
/// </para>
/// <para>
/// It mutates <see cref="GraphNode.IsHot"/> on the nodes it is given, rather than returning a
/// parallel set, so the caller persists the same rows it queried. <see cref="GraphSeeder"/>
/// applies the identical severity threshold to the SEC-16 node set; the constant lives there and
/// is referenced here so the two can never drift.
/// </para>
/// </remarks>
public sealed class GraphDecorator(ILogger<GraphDecorator> logger)
{
    /// <summary>
    /// Attaches <paramref name="findings"/> to <paramref name="nodes"/>.
    /// </summary>
    /// <param name="infraLocationToNodeKey">Finding location → node key for infrastructure
    /// findings, from <see cref="Domain.Abstractions.IInfraFindingLocator"/>. Empty when the
    /// bundle carried no Terraform: infra findings then stay unattached, which is honest, rather
    /// than being spread over whatever infra nodes happen to exist.</param>
    public DecoratedGraph Decorate(
        IReadOnlyList<GraphNode> nodes,
        IReadOnlyList<Finding> findings,
        IReadOnlyDictionary<string, string>? infraLocationToNodeKey = null)
    {
        ArgumentNullException.ThrowIfNull(nodes);
        ArgumentNullException.ThrowIfNull(findings);

        var nodesByKey = nodes
            .GroupBy(n => n.NodeKey, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);

        var codeIdentifiers = nodesByKey.Values
            .Where(n => n.NodeType == NodeType.Code)
            .ToDictionary(n => IdentifierOf(n.NodeKey), n => n.NodeKey, StringComparer.Ordinal);

        var attached = new Dictionary<string, List<Finding>>(StringComparer.Ordinal);
        var unattached = new List<Finding>();

        foreach (var finding in findings)
        {
            var nodeKey = Resolve(finding, nodesByKey, codeIdentifiers, infraLocationToNodeKey);

            if (nodeKey is null)
            {
                unattached.Add(finding);
                continue;
            }

            if (!attached.TryGetValue(nodeKey, out var list))
                attached[nodeKey] = list = [];

            list.Add(finding);

            // One hot finding is enough; a later cool one must not cool the node back down.
            if (finding.Severity >= GraphSeeder.HotSeverity) nodesByKey[nodeKey].IsHot = true;
        }

        if (unattached.Count > 0)
        {
            logger.LogInformation(
                "{Count} of {Total} finding(s) could not be attached to a graph node and cannot "
                + "seed or decorate a chain", unattached.Count, findings.Count);
        }

        var hot = nodesByKey.Values.Count(n => n.IsHot);
        logger.LogInformation(
            "Decorated {Decorated} of {Nodes} node(s); {Hot} are hot", attached.Count, nodesByKey.Count, hot);

        return new DecoratedGraph(
            attached.ToDictionary(
                e => e.Key,
                e => (IReadOnlyList<Finding>)[.. e.Value.OrderByDescending(f => f.Severity)],
                StringComparer.Ordinal),
            unattached);
    }

    /// <summary>
    /// The node key this finding decorates, or null when nothing places it.
    /// </summary>
    private static string? Resolve(
        Finding finding,
        IReadOnlyDictionary<string, GraphNode> nodesByKey,
        IReadOnlyDictionary<string, string> codeIdentifiers,
        IReadOnlyDictionary<string, string>? infraLocationToNodeKey)
    {
        // 1. The reference already names a node. True for anything the SEC-16 node set and a
        //    seam reader happen to agree on, and the only rule that needs no justification.
        if (nodesByKey.ContainsKey(finding.NodeRef)) return finding.NodeRef;

        if (!NodeId.TryParse(finding.NodeRef, out var nodeType, out var identifier)) return null;

        return nodeType switch
        {
            // 2. A package finding is keyed name:version because a scanner reports the exact
            //    version it found; the lock file's node is keyed by name, because that is the
            //    package regardless of which version resolved. Same package, so drop the
            //    version — never the reverse, since guessing a version onto a node key would
            //    invent a coordinate nothing reported.
            NodeType.Pkg => Match(nodesByKey, NodeId.Package(NameOf(identifier))),

            // 3. A code finding is keyed by file path; the code node is keyed by the project
            //    directory that owns the build files (see ProvisionalCodeNodeResolver). The file
            //    belongs to the project when the project's directory is one of the path's own
            //    segments — the deepest such segment, so a nested project wins over the
            //    repository root it sits under.
            NodeType.Code => ProjectOf(identifier, codeIdentifiers),

            // 4. An infra finding is keyed by .tf file; the infra nodes are keyed by Terraform
            //    resource. Only the locator can bridge that, because only it parses the source.
            NodeType.Resource when finding.Location is { } location =>
                infraLocationToNodeKey is not null && infraLocationToNodeKey.TryGetValue(location, out var key)
                    ? Match(nodesByKey, key)
                    : null,

            _ => null,
        };
    }

    private static string? Match(IReadOnlyDictionary<string, GraphNode> nodesByKey, string candidate) =>
        nodesByKey.ContainsKey(candidate) ? candidate : null;

    /// <summary>The package name out of a <c>name:version</c> identifier.</summary>
    private static string NameOf(string identifier)
    {
        var separator = identifier.IndexOf(NodeId.Separator);
        return separator > 0 ? identifier[..separator] : identifier;
    }

    /// <summary>
    /// The code node whose identifier is the deepest directory segment of this file path.
    /// </summary>
    private static string? ProjectOf(string path, IReadOnlyDictionary<string, string> codeIdentifiers)
    {
        string? match = null;

        // The file name itself is excluded: a file called OrderApp.cs inside a different project
        // must not be claimed by the OrderApp project.
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < segments.Length - 1; i++)
        {
            if (codeIdentifiers.TryGetValue(segments[i], out var nodeKey)) match = nodeKey;
        }

        return match;
    }

    /// <summary>The identifier half of a canonical key, for a key already known to be canonical.</summary>
    private static string IdentifierOf(string nodeKey) =>
        NodeId.TryParse(nodeKey, out _, out var identifier) ? identifier : nodeKey;
}

/// <summary>The result of one decoration pass.</summary>
/// <param name="FindingsByNodeKey">Node key → its findings, most severe first. Nodes nothing
/// landed on are absent rather than mapped to an empty list.</param>
/// <param name="Unattached">Findings no rule could place. Kept rather than dropped so a caller
/// can report the gap — a growing count here means the granularity rules have fallen behind the
/// extractors again.</param>
public sealed record DecoratedGraph(
    IReadOnlyDictionary<string, IReadOnlyList<Finding>> FindingsByNodeKey,
    IReadOnlyList<Finding> Unattached);

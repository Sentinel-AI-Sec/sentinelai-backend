using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Application.Features.Scan.Normalization;

/// <summary>
/// The Unify step (SEC-16): turns every scanner's normalized findings into one deduplicated
/// set in which every finding carries a canonical <see cref="Finding.NodeRef"/> — the single
/// input the graph and retrieval stages consume.
/// </summary>
/// <remarks>
/// Deliberately pure: a list in, a list out, no I/O and no clock. Unification is where an
/// over-eager grouping key silently deletes real vulnerabilities, so it is written to be
/// exercised by plain unit tests rather than only through the pipeline.
/// </remarks>
public sealed class FindingUnifier
{
    /// <summary>
    /// Merges, deduplicates, and stamps a node reference on every finding.
    /// </summary>
    /// <remarks>
    /// When a group does collapse, the survivor is the most severe member rather than whichever
    /// happened to be read first: two reports of one problem can disagree on severity, and
    /// keeping the lower one would quietly downgrade a finding on the strength of file
    /// ordering.
    /// </remarks>
    public IReadOnlyList<Finding> Unify(IEnumerable<Finding> findings)
    {
        var unified = findings
            .GroupBy(DedupKey)
            .Select(group => group.MaxBy(f => f.Severity)!)
            .ToList();

        foreach (var finding in unified)
            finding.NodeRef = NodeRefFor(finding);

        return unified;
    }

    /// <summary>
    /// What makes two findings the same finding: the same tool reported the same rule about
    /// the same place, saying the same thing.
    /// </summary>
    /// <remarks>
    /// The rule id and the location both have to be in the key, in both directions.
    /// <list type="bullet">
    /// <item>Without the <em>rule id</em>, Checkov's CKV_AWS_288, _289 and _290 — three
    /// different IAM weaknesses it reports on the identical Terraform line — would collapse
    /// into one, and two of the three would vanish with nothing logged.</item>
    /// <item>Without the <em>location</em>, one rule that legitimately fires on four different
    /// S3 buckets would collapse into one bucket's worth of risk.</item>
    /// </list>
    /// The message is the tie-breaker that carries the load when a tool reports no rule id and
    /// no location, so the key never degenerates to "everything from this tool".
    /// <para>
    /// The <see cref="Finding.CveId"/> is in the key because Trivy reports several distinct
    /// CVEs against one package at one lock-file line: same tool, same location, different
    /// vulnerability.
    /// </para>
    /// </remarks>
    private static (string, string, string, string, string) DedupKey(Finding f) =>
    (
        f.SourceTool.ToLowerInvariant(),
        f.CheckId?.ToLowerInvariant() ?? string.Empty,
        f.CveId?.ToLowerInvariant() ?? string.Empty,
        f.Location?.ToLowerInvariant() ?? string.Empty,
        f.Message
    );

    /// <summary>
    /// Builds the canonical key of the graph node this finding decorates, always through
    /// <see cref="NodeId"/> — never by string concatenation (SEC-03).
    /// </summary>
    /// <remarks>
    /// <para>The node type follows the layer: a dependency finding decorates a package, a code
    /// finding decorates the code, an infrastructure finding decorates a resource.</para>
    /// <para>
    /// The identifier is file-grained, because a file path is the finest subject the scanners
    /// actually report: Checkov's SARIF names <c>infra/iam.tf</c>, not the
    /// <c>aws_iam_role_policy.order_task_policy</c> block inside it. When the Terraform and
    /// code readers land (SEC-17/SEC-18) they will emit resource- and symbol-grained nodes, and
    /// this mapping tightens to match them. What must hold today, and does, is that the key is
    /// canonical, deterministic, and identical for the same finding scanned on two different
    /// machines.
    /// </para>
    /// </remarks>
    public static string NodeRefFor(Finding finding)
    {
        var subject = finding.Location;

        if (string.IsNullOrWhiteSpace(subject))
            return NodeId.For(TypeFor(finding.Layer), Anonymous(finding));

        return finding.Layer switch
        {
            // A dependency location is a package coordinate, name@version. The canonical
            // package key separates the two with ':' — pkg:commons-collections:3.2.1 —
            // and NodeId.TryParse splits on the first ':' only, so the version survives.
            Layer.Dep => NodeId.Package(subject.Replace('@', NodeId.Separator)),

            // A code or infra location is a path, possibly with a line. The node is the file,
            // not the line: infra/iam.tf:25 and infra/iam.tf:41 decorate the same node.
            _ => NodeId.For(TypeFor(finding.Layer), StripLine(subject)),
        };
    }

    private static NodeType TypeFor(Layer layer) => layer switch
    {
        Layer.Dep => NodeType.Pkg,
        Layer.Infra => NodeType.Resource,
        _ => NodeType.Code,
    };

    /// <summary>
    /// A deterministic key for a finding whose tool reported no location at all.
    /// </summary>
    /// <remarks>
    /// Every finding must carry a node ref for the graph to be able to attach it, so a
    /// location-less finding gets a key built from its rule id rather than an empty string.
    /// It will not join to a real node — nothing can join a finding that never said where it
    /// was — but it is visibly a placeholder rather than a finding that silently fell out of
    /// the graph.
    /// </remarks>
    private static string Anonymous(Finding finding)
        => !string.IsNullOrWhiteSpace(finding.CheckId) ? $"{finding.SourceTool}/{finding.CheckId}"
         : !string.IsNullOrWhiteSpace(finding.CveId) ? $"{finding.SourceTool}/{finding.CveId}"
         : $"{finding.SourceTool}/{finding.Id}";

    /// <summary>
    /// Drops a trailing <c>:line</c>, and only that — a path may contain other colons, and
    /// splitting on all of them would cut a Windows path at its drive letter.
    /// </summary>
    private static string StripLine(string location)
    {
        var lastColon = location.LastIndexOf(NodeId.Separator);
        if (lastColon <= 0 || lastColon == location.Length - 1)
            return location;

        var tail = location[(lastColon + 1)..];
        return tail.All(char.IsAsciiDigit) ? location[..lastColon] : location;
    }
}

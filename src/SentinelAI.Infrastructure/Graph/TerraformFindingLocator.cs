using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-20's half of the node-granularity fix: places a Checkov/Trivy infrastructure finding on
/// the Terraform resource it is actually about, by looking up the block its reported line falls
/// inside.
/// </summary>
/// <remarks>
/// <para>
/// Two resolutions, in order:
/// </para>
/// <list type="number">
/// <item><b>The block itself has a canonical node type.</b> <c>infra/main.tf:42</c> lands inside
/// <c>aws_ecs_task_definition.order_task</c> → <c>task:order_task</c>. Direct and exact.</item>
/// <item><b>The block is a sub-resource that configures another one.</b> Checkov's IAM findings
/// land on <c>aws_iam_role_policy.order_task_policy</c>, and its S3 encryption/versioning
/// findings on <c>aws_s3_bucket_versioning.x</c> — resource types with no canonical
/// <see cref="Domain.Enums.NodeType"/> (a SEC-03 decision, not this ticket's). Those blocks
/// exist only to configure a resource that <em>does</em> have one, and they name it literally
/// (<c>role = aws_iam_role.order_task_role.id</c>), so the finding decorates that resource. This
/// is the step that makes the fixture's flagship IAM finding land on
/// <c>iam_role:order_task_role</c> and so makes it a hot seed.</item>
/// </list>
/// <para>
/// Anything else is left unresolved and the caller leaves the finding unattached. A finding
/// placed on the wrong node is worse than one placed on none: it invents a seed, and every
/// candidate chain grown from that seed is fiction.
/// </para>
/// </remarks>
public sealed partial class TerraformFindingLocator(ILogger<TerraformFindingLocator> logger) : IInfraFindingLocator
{
    [GeneratedRegex(@"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.CultureInvariant)]
    private static partial Regex DottedReference();

    public IReadOnlyDictionary<string, string> Locate(
        IReadOnlyDictionary<string, string> hclFiles, IEnumerable<string> findingLocations)
    {
        ArgumentNullException.ThrowIfNull(hclFiles);
        ArgumentNullException.ThrowIfNull(findingLocations);

        var resolved = new Dictionary<string, string>(StringComparer.Ordinal);
        if (hclFiles.Count == 0) return resolved;

        var blocksByFile = hclFiles.ToDictionary(
            f => Normalize(f.Key), f => TerraformBlockLocator.Index(f.Value), StringComparer.OrdinalIgnoreCase);

        // Every declared address across every file, since a sub-resource in one file routinely
        // references the resource it configures in another.
        var declared = blocksByFile.Values
            .SelectMany(blocks => blocks)
            .GroupBy(b => b.Address, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);

        foreach (var location in findingLocations.Distinct(StringComparer.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(location) || resolved.ContainsKey(location)) continue;

            var (path, line) = SplitLine(location);
            if (FindFile(blocksByFile, path) is not { } blocks) continue;

            var block = line is { } l
                ? TerraformBlockLocator.BlockAt(blocks, l)
                : SoleMappableBlock(blocks);

            if (block is null) continue;

            if (NodeKeyFor(block) is { } key)
            {
                resolved[location] = key;
                continue;
            }

            if (ConfiguredResourceKey(block, declared) is { } referenced)
            {
                logger.LogDebug(
                    "Finding at {Location} sits in {Address}, which has no canonical node type; " +
                    "attaching it to {NodeKey}, the resource that block configures",
                    location, block.Address, referenced);
                resolved[location] = referenced;
            }
        }

        return resolved;
    }

    /// <summary>The block's own canonical node key, when its resource type has one.</summary>
    private static string? NodeKeyFor(TerraformBlock block) =>
        TerraformResourceTypeMap.TryMap(block.ResourceType, out var nodeType)
            ? NodeId.For(nodeType, block.ResourceName)
            : null;

    /// <summary>
    /// The node key of the first mappable resource this block references — the resource it
    /// configures.
    /// </summary>
    /// <remarks>
    /// First rather than best: a sub-resource block configures exactly one resource, and the
    /// literal reference to it is the first mappable <c>type.name</c> in the body in every shape
    /// this fixture's Terraform uses. A block referencing two mappable resources would be
    /// ambiguous, and picking arbitrarily between them would be exactly the invented-seed
    /// failure this class's remarks warn about — but it would also be unusual Terraform, so it
    /// is left as a known limit rather than guessed at.
    /// </remarks>
    private static string? ConfiguredResourceKey(
        TerraformBlock block, IReadOnlyDictionary<string, TerraformBlock> declared)
    {
        foreach (Match reference in DottedReference().Matches(block.Body))
        {
            var address = $"{reference.Groups[1].Value}.{reference.Groups[2].Value}";
            if (address == block.Address) continue;
            if (!declared.TryGetValue(address, out var target)) continue;

            if (NodeKeyFor(target) is { } key) return key;
        }

        return null;
    }

    /// <summary>
    /// The one block a finding with no line number can safely be attributed to: the file's only
    /// mappable resource. Two or more and there is no way to tell which was meant.
    /// </summary>
    private static TerraformBlock? SoleMappableBlock(IReadOnlyList<TerraformBlock> blocks)
    {
        TerraformBlock? only = null;

        foreach (var block in blocks)
        {
            if (!TerraformResourceTypeMap.TryMap(block.ResourceType, out _)) continue;
            if (only is not null) return null;
            only = block;
        }

        return only;
    }

    /// <summary>
    /// The indexed file whose path ends with the finding's path.
    /// </summary>
    /// <remarks>
    /// Suffix, not equality: the bundle stores <c>graph-inputs/infra/iam.tf</c> while Checkov
    /// reported <c>infra/iam.tf</c>, and neither side is wrong about its own root. The longest
    /// matching suffix wins so that <c>infra/iam.tf</c> never matches <c>other/infra/iam.tf</c>
    /// in preference to the real one when both are present.
    /// </remarks>
    private static IReadOnlyList<TerraformBlock>? FindFile(
        IReadOnlyDictionary<string, IReadOnlyList<TerraformBlock>> blocksByFile, string path)
    {
        if (blocksByFile.TryGetValue(path, out var exact)) return exact;

        IReadOnlyList<TerraformBlock>? best = null;
        var bestLength = int.MaxValue;

        foreach (var (file, blocks) in blocksByFile)
        {
            if (!file.EndsWith('/' + path, StringComparison.OrdinalIgnoreCase)) continue;
            if (file.Length >= bestLength) continue;

            best = blocks;
            bestLength = file.Length;
        }

        return best;
    }

    /// <summary>Splits <c>path:line</c>, tolerating a bare path.</summary>
    private static (string Path, int? Line) SplitLine(string location)
    {
        var normalized = Normalize(location);
        var lastColon = normalized.LastIndexOf(':');

        if (lastColon > 0 && int.TryParse(normalized[(lastColon + 1)..], out var line) && line > 0)
            return (normalized[..lastColon], line);

        return (normalized, null);
    }

    private static string Normalize(string path) => path.Replace('\\', '/').Trim('/');
}

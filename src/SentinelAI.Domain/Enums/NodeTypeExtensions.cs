namespace SentinelAI.Domain.Enums;

/// <summary>
/// The wire spelling of each <see cref="NodeType"/> — the prefix that appears in a
/// canonical node key.
/// </summary>
/// <remarks>
/// These strings cross repository boundaries: the GitHub Action, the fixtures and the
/// knowledge corpus all mirror them, so a node key written by one extractor matches a node
/// key written by another. Changing one is a cross-repo breaking change, not a rename —
/// which is exactly why they live in one switch instead of scattered string literals.
/// </remarks>
public static class NodeTypeExtensions
{
    /// <summary>The canonical prefix, e.g. <see cref="NodeType.IamRole"/> → <c>iam_role</c>.</summary>
    public static string Prefix(this NodeType type) => type switch
    {
        NodeType.Pkg => "pkg",
        NodeType.Code => "code",
        NodeType.Image => "image",
        NodeType.Task => "task",
        NodeType.IamRole => "iam_role",

        // Historical: the design document specifies "s3" because the demo fixture's crown
        // jewel is a bucket. Kept as-is deliberately — SEC-04's fixtures and SEC-06's corpus
        // already emit it, so widening it to "resource" is a team decision, not a cleanup.
        NodeType.Resource => "s3",

        _ => throw new ArgumentOutOfRangeException(
            nameof(type), type, "No canonical prefix defined for this node type."),
    };

    /// <summary>The inverse of <see cref="Prefix"/>. Case-insensitive.</summary>
    public static bool TryFromPrefix(string? prefix, out NodeType type)
    {
        foreach (var candidate in Enum.GetValues<NodeType>())
        {
            if (string.Equals(candidate.Prefix(), prefix, StringComparison.OrdinalIgnoreCase))
            {
                type = candidate;
                return true;
            }
        }

        type = default;
        return false;
    }
}

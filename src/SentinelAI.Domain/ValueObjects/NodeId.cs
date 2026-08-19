using SentinelAI.Domain.Enums;

namespace SentinelAI.Domain.ValueObjects;

/// <summary>
/// The ONE way to build a node id. Nobody builds ids by hand.
/// </summary>
/// <remarks>
/// The rule is <c>type:identifier</c>, always trimmed, always lower-cased. It exists because
/// two extractors describing the same resource must produce byte-identical keys — if the
/// Terraform reader emits <c>iam_role:Order</c> and the finding normalizer emits
/// <c>iam_role:order</c>, the graph splits into disconnected islands and no attack chain is
/// ever found, with no error message. That failure is silent, which is why the rule is
/// centralized and tested rather than documented and hoped for (SEC-03).
/// <para>
/// There is deliberately no <c>For(string type, ...)</c> overload. Taking the type as a
/// <see cref="NodeType"/> is what makes an invented type a compile error instead of a
/// disconnected island.
/// </para>
/// </remarks>
public static class NodeId
{
    /// <summary>Separates the type from the identifier.</summary>
    public const char Separator = ':';

    /// <summary>Builds a canonical node key.</summary>
    /// <exception cref="ArgumentException">The identifier is blank.</exception>
    public static string For(NodeType type, string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        return $"{type.Prefix()}{Separator}{Normalize(identifier)}";
    }

    public static string Package(string name) => For(NodeType.Pkg, name);
    public static string Code(string name) => For(NodeType.Code, name);
    public static string Image(string name) => For(NodeType.Image, name);
    public static string Task(string name) => For(NodeType.Task, name);
    public static string Role(string name) => For(NodeType.IamRole, name);
    public static string Resource(string name) => For(NodeType.Resource, name);

    /// <summary>
    /// Reads a node key back into its parts, so a consumer joining findings to nodes does
    /// not have to split on <c>':'</c> by hand and re-invent the normalization.
    /// </summary>
    /// <remarks>
    /// Splits on the FIRST separator only: identifiers legitimately contain colons
    /// (<c>pkg:commons-collections:3.2.1</c>), so splitting on all of them would truncate
    /// the version.
    /// </remarks>
    public static bool TryParse(string? nodeKey, out NodeType type, out string identifier)
    {
        type = default;
        identifier = string.Empty;

        if (string.IsNullOrWhiteSpace(nodeKey)) return false;

        var split = nodeKey.IndexOf(Separator);
        if (split <= 0 || split == nodeKey.Length - 1) return false;

        if (!NodeTypeExtensions.TryFromPrefix(nodeKey[..split], out type)) return false;

        identifier = Normalize(nodeKey[(split + 1)..]);
        return identifier.Length > 0;
    }

    /// <summary>True when the key is one this codebase could have produced.</summary>
    public static bool IsCanonical(string? nodeKey) =>
        TryParse(nodeKey, out var type, out var identifier)
        && string.Equals(nodeKey, For(type, identifier), StringComparison.Ordinal);

    private static string Normalize(string value) => value.Trim().ToLowerInvariant();
}

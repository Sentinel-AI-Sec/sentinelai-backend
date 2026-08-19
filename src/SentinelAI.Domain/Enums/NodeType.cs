namespace SentinelAI.Domain.Enums;

/// <summary>
/// The kind of thing a graph node represents. This is the type half of a canonical
/// node key (<c>type:identifier</c>) — see <see cref="ValueObjects.NodeId"/>.
/// </summary>
/// <remarks>
/// The member set is the whole vocabulary. Adding a node kind means adding a member here
/// and a prefix in <see cref="NodeTypeExtensions.Prefix"/>, which is what stops one
/// extractor writing <c>role:order</c> while another writes <c>iam_role:order</c> and the
/// graph silently splitting into disconnected islands (SEC-03).
/// </remarks>
public enum NodeType
{
    /// <summary>A dependency package, e.g. <c>commons-collections:3.2.1</c>.</summary>
    Pkg,

    /// <summary>A code symbol, e.g. a method that deserializes untrusted input.</summary>
    Code,

    /// <summary>A container image.</summary>
    Image,

    /// <summary>A deployed workload, e.g. an ECS task definition.</summary>
    Task,

    /// <summary>An IAM role.</summary>
    IamRole,

    /// <summary>A cloud resource holding data, e.g. a crown-jewel bucket.</summary>
    Resource,
}

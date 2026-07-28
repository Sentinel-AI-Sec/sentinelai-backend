namespace SentinelAI.Domain.ValueObjects;

// The ONE way to build a node id. Nobody builds ids by hand.
public static class NodeId
{
    public static string For(string type, string identifier)
        => $"{type.Trim().ToLowerInvariant()}:{identifier.Trim().ToLowerInvariant()}";

    public static string Package(string name)  => For("pkg", name);
    public static string Code(string name)     => For("code", name);
    public static string Image(string name)    => For("image", name);
    public static string Task(string name)     => For("task", name);
    public static string Role(string name)     => For("iam_role", name);
    public static string Resource(string name) => For("s3", name);
}

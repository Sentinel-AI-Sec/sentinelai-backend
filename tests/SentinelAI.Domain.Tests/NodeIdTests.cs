using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Domain.Tests;

/// <summary>
/// SEC-03's central invariant: two components describing the same resource must produce
/// byte-identical node keys.
/// </summary>
/// <remarks>
/// The failure this guards is silent. Mismatched keys do not throw — the graph just splits
/// into disconnected islands and reports zero attack chains, which looks exactly like a
/// clean scan. There is no runtime signal, so the test is the signal.
/// </remarks>
public class NodeIdTests
{
    // The canonical example from the SEC-03 spec: Terraform yields a capitalized role name,
    // the finding normalizer yields a padded one, and both must land on iam_role:order.
    [Fact]
    public void Two_extractors_produce_the_same_node_id()
    {
        var fromTerraform = NodeId.Role("Order");
        var fromFinding = NodeId.Role(" order ");

        Assert.Equal(fromTerraform, fromFinding);
        Assert.Equal("iam_role:order", fromTerraform);
    }

    [Theory]
    [InlineData(NodeType.Pkg, "pkg")]
    [InlineData(NodeType.Code, "code")]
    [InlineData(NodeType.Image, "image")]
    [InlineData(NodeType.Task, "task")]
    [InlineData(NodeType.IamRole, "iam_role")]
    [InlineData(NodeType.Resource, "s3")]
    public void Every_node_type_has_a_pinned_wire_prefix(NodeType type, string expected)
    {
        Assert.Equal(expected, type.Prefix());
        Assert.Equal($"{expected}:thing", NodeId.For(type, "Thing"));
    }

    // Adding an enum member without a prefix would otherwise fail at runtime, in whichever
    // extractor happened to hit it first.
    [Fact]
    public void No_node_type_is_missing_a_prefix()
    {
        foreach (var type in Enum.GetValues<NodeType>())
        {
            Assert.False(string.IsNullOrWhiteSpace(type.Prefix()));
            Assert.True(NodeTypeExtensions.TryFromPrefix(type.Prefix(), out var round));
            Assert.Equal(type, round);
        }
    }

    // A package identifier contains its own colon. Splitting on every separator would drop
    // the version and merge 3.2.1 with 3.2.2 — a fixed CVE reported as still present.
    [Fact]
    public void Parsing_keeps_colons_inside_the_identifier()
    {
        var key = NodeId.Package("commons-collections:3.2.1");

        Assert.True(NodeId.TryParse(key, out var type, out var identifier));
        Assert.Equal(NodeType.Pkg, type);
        Assert.Equal("commons-collections:3.2.1", identifier);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("no-separator")]
    [InlineData(":leading")]
    [InlineData("trailing:")]
    [InlineData("role:order")]      // the wrong spelling the spec calls out by name
    [InlineData("bucket:customers")]
    public void A_key_this_codebase_could_not_have_written_is_rejected(string? key)
    {
        Assert.False(NodeId.TryParse(key, out _, out _));
        Assert.False(NodeId.IsCanonical(key));
    }

    [Fact]
    public void A_hand_built_key_that_skipped_normalization_is_not_canonical()
    {
        // What someone writing "iam_role:" + name by hand produces.
        Assert.False(NodeId.IsCanonical("iam_role:Order"));
        Assert.True(NodeId.IsCanonical(NodeId.Role("Order")));
    }

    [Fact]
    public void A_blank_identifier_fails_loudly_rather_than_producing_a_prefix_only_key()
    {
        Assert.Throws<ArgumentException>(() => NodeId.Role("  "));
    }

    // The brief is what the agents learn the vocabulary from. When it said
    // "iam-role:api-task-role", Red asserted chains using node ids the real graph will never
    // contain — and nothing would have caught it until the graph builder landed and returned
    // zero matches. Cheap to assert here; expensive to find there.
    [Fact]
    public void Every_node_id_in_the_debate_brief_is_canonical()
    {
        var nodeLine = ScanBrief.Stub().Context
            .Split('\n')
            .Single(l => l.StartsWith("Nodes:", StringComparison.Ordinal));

        var keys = nodeLine["Nodes:".Length..]
            .Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(entry => entry[(entry.IndexOf('=') + 1)..].Trim())
            .ToArray();

        Assert.Equal(5, keys.Length);
        Assert.All(keys, key => Assert.True(
            NodeId.IsCanonical(key),
            $"'{key}' is not a node id this codebase could produce."));
    }

    [Fact]
    public void Graph_node_factory_keeps_key_and_type_in_agreement()
    {
        var node = GraphNode.Create(Guid.NewGuid(), Guid.NewGuid(), NodeType.Resource, "Customer-Data-Bucket", Layer.Infra);

        Assert.Equal("s3:customer-data-bucket", node.NodeKey);
        Assert.True(NodeId.TryParse(node.NodeKey, out var parsed, out _));
        Assert.Equal(node.NodeType, parsed);
    }
}

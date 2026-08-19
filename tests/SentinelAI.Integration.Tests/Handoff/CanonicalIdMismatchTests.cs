using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Integration.Tests.Handoff;

/// <summary>
/// The deliberate-break test. Feed the graph a finding whose node id uses a non-canonical prefix
/// (<c>role:order</c> instead of <c>iam_role:order</c>) and prove the pipeline catches it, rather
/// than silently producing a disconnected island and zero chains.
/// </summary>
/// <remarks>
/// <para>
/// This is the whole reason SEC-47 exists. In the POC, one stage wrote <c>iam_role:order</c> and
/// another looked up <c>role:order</c>; nothing threw, the finding never joined the graph, and the
/// scan reported zero exploit chains that looked exactly like a clean result. The guard here turns
/// that silent island into a loud failure at the seam.
/// </para>
/// <para>
/// The current guard is <em>louder</em> than the ticket's "lookup returns null": <see cref="GraphSeeder"/>
/// throws rather than dropping the finding, because a dropped finding is invisible to every later
/// stage and silence is the exact failure mode. The contrast test proves the guard discriminates —
/// the canonical key attaches, the broken one does not.
/// </para>
/// <para>
/// <b>What this file does not cover, and cannot.</b> Every case here is a <em>syntactically</em>
/// wrong key, and the guard is a syntax check. The island split that actually happened in this
/// codebase was two keys that are both perfectly canonical at different granularities —
/// <c>pkg:newtonsoft.json:12.0.1</c> from the unifier against <c>pkg:newtonsoft.json</c> from the
/// lock file. <see cref="NodeId.IsCanonical"/> is true of both, nothing throws, and the guard
/// below is silent, as the last test here demonstrates rather than leaves implied. Catching that
/// needs a measurement, not an exception, and that lives in
/// <see cref="CommittedFixtureGranularityTests"/>.
/// </para>
/// </remarks>
public class CanonicalIdMismatchTests
{
    private readonly GraphSeeder _graph = new();

    [Theory]
    [InlineData("role:order")]          // wrong prefix — "role" is not a node type; "iam_role" is
    [InlineData("iam_role:Order")]      // right prefix, but hand-built and never normalized (upper O)
    [InlineData("Code:OrderService")]   // the SEC-03 example: capitalized, so it is not canonical
    public void A_finding_with_a_non_canonical_node_id_fails_to_attach_loudly(string brokenNodeRef)
    {
        var finding = HandoffFixture.SeededFinding();
        finding.NodeRef = brokenNodeRef;

        // It never reaches the graph as an orphan node — the seam refuses it and says why.
        var ex = Assert.Throws<InvalidOperationException>(
            () => _graph.Seed([finding], HandoffFixture.Tenant, HandoffFixture.Job));

        Assert.Contains(brokenNodeRef, ex.Message, StringComparison.Ordinal);
        Assert.Contains("join the graph", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_guard_discriminates_the_canonical_key_attaches_where_the_broken_one_does_not()
    {
        // Same resource, same intent — the only difference is the prefix. This is the island bug in
        // miniature: one spelling joins, the other cannot, and without the guard neither would error.
        var canonical = HandoffFixture.SeededFinding();
        canonical.NodeRef = NodeId.Role("order");            // iam_role:order — the real key

        var broken = HandoffFixture.SeededFinding();
        broken.NodeRef = "role:order";                       // the mismatch that split the POC's graph

        var node = Assert.Single(_graph.Seed([canonical], HandoffFixture.Tenant, HandoffFixture.Job));
        Assert.Equal("iam_role:order", node.NodeKey);
        Assert.Equal(NodeType.IamRole, node.NodeType);

        Assert.Throws<InvalidOperationException>(
            () => _graph.Seed([broken], HandoffFixture.Tenant, HandoffFixture.Job));

        // And the two keys really are different strings — the silent failure was that nothing ever
        // compared them.
        Assert.NotEqual(canonical.NodeRef, broken.NodeRef);
    }

    /// <summary>
    /// The limit of this guard, asserted rather than assumed: two canonical keys at different
    /// granularities are not a mismatch it can see.
    /// </summary>
    /// <remarks>
    /// This test passes today and is meant to. It is here so nobody reads the rest of the file and
    /// concludes the island bug is covered. The finding's ref is version-grained because a scanner
    /// reports the version it found; the node is name-grained because the lock file's node is the
    /// package whatever version resolved. Both are what <see cref="NodeId"/> would build, so
    /// <see cref="GraphSeeder"/> accepts the finding, produces a node nothing else shares, and the
    /// graph quietly holds two islands. The join that closes it is
    /// <c>GraphDecorator</c>'s, and whether it still closes on the real fixture is measured in
    /// <see cref="CommittedFixtureGranularityTests"/>.
    /// </remarks>
    [Fact]
    public void The_guard_is_silent_when_both_spellings_are_canonical_at_different_granularities()
    {
        var scannerRef = NodeId.Package("newtonsoft.json:12.0.1");   // what FindingUnifier emits
        var lockFileKey = NodeId.Package("newtonsoft.json");         // what DepCodeSeamReader emits

        Assert.True(NodeId.IsCanonical(scannerRef));
        Assert.True(NodeId.IsCanonical(lockFileKey));
        Assert.NotEqual(scannerRef, lockFileKey);

        var finding = HandoffFixture.SeededFinding();
        finding.NodeRef = scannerRef;

        // No throw, no warning, no null lookup — an island, built successfully.
        var node = Assert.Single(_graph.Seed([finding], HandoffFixture.Tenant, HandoffFixture.Job));
        Assert.Equal(scannerRef, node.NodeKey);
        Assert.NotEqual(lockFileKey, node.NodeKey);
    }
}

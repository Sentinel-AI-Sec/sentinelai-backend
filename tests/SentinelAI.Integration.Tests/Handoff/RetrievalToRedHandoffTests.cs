using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Handoff;

/// <summary>
/// Boundary 3 — Retrieval → Red. What the debate hands Red is the <see cref="ScanBrief"/>: the
/// canonical nodes and the retrieved knowledge, with the hop slots (technique / evidence) left
/// empty for Red to fill.
/// </summary>
/// <remarks>
/// <para>
/// The ticket frames this boundary as "candidate chains arrive with nodes + confidence and empty
/// technique/evidence slots." In the current pipeline the candidate structure Red reasons over is
/// the rendered brief, not typed <c>Chain</c>/<c>ChainHop</c> objects (those are populated by
/// candidate-chain generation, SEC-17/18, which does not exist yet). So this asserts the real
/// object crossing the seam: the brief carries the canonical node vocabulary and states plainly
/// that no edges/hops are pre-filled — Red is the one that asserts them.
/// </para>
/// <para>
/// The load-bearing check is that node ids appear in the brief <em>verbatim and canonical</em>.
/// This text is where the agents learn the vocabulary; a key re-spelled here (<c>iam-role:</c> for
/// <c>iam_role:</c>) is how Red comes to assert chains whose ids the real graph can never match.
/// </para>
/// </remarks>
public class RetrievalToRedHandoffTests
{
    [Fact]
    public async Task Red_receives_a_brief_carrying_the_canonical_nodes_and_the_knowledge()
    {
        var capture = new CapturingDebate();
        var pipeline = HandoffFixture.BuildPipeline(debate: capture);

        await pipeline.RunAsync([HandoffFixture.SeededFinding()], HandoffFixture.Tenant, HandoffFixture.Job);

        var brief = capture.Received;
        Assert.NotNull(brief);
        Assert.Equal(HandoffFixture.Job.ToString(), brief!.ScanJobId);

        // The node vocabulary is present, verbatim and canonical.
        Assert.Contains("code:orderservice", brief.Context, StringComparison.Ordinal);
        Assert.Contains("CWE-502", brief.Context, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_brief_leaves_the_hop_slots_empty_for_red_to_fill()
    {
        var capture = new CapturingDebate();
        var pipeline = HandoffFixture.BuildPipeline(debate: capture);

        await pipeline.RunAsync([HandoffFixture.SeededFinding()], HandoffFixture.Tenant, HandoffFixture.Job);

        var context = capture.Received!.Context;

        // No edges were extracted for the seeded slice, and the brief says so rather than leaving
        // it implicit — an agent handed nodes with no stated edge policy infers edges, and an
        // inferred edge is a fabricated hop. This is the "empty slots" contract.
        Assert.Contains("Edges:", context, StringComparison.Ordinal);
        Assert.Contains("Do not infer", context, StringComparison.OrdinalIgnoreCase);

        // Nothing is pre-chained: the brief carries no asserted hop / technique / evidence. Those
        // are Red's output, and finding them here would mean the boundary pre-populated Red's job.
        Assert.DoesNotContain(" -> ", context, StringComparison.Ordinal);
        Assert.DoesNotContain("technique", context, StringComparison.OrdinalIgnoreCase);
    }
}

using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Tests.Scan.Graph;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// SEC-21's second acceptance box: the shape a candidate chain is handed over in.
/// </summary>
/// <remarks>
/// The candidates are produced by the real <see cref="ExploitChainTraverser"/> over the fixture's
/// flagship graph rather than being hand-built. The handoff's whole job is to carry what the
/// traverser produced without altering it, and a hand-built candidate would let this file agree
/// with itself while disagreeing with the stage it is supposed to receive from.
/// </remarks>
public class AttackGraphHandoffTests
{
    private static readonly ExploitChainTraverser Traverser =
        new(NullLogger<ExploitChainTraverser>.Instance);

    private static readonly string Package = NodeId.Package("newtonsoft.json");
    private static readonly string Code = NodeId.Code("orderapp");
    private static readonly string Task = NodeId.Task("order_task");
    private static readonly string Role = NodeId.Role("order_task_role");
    private static readonly string Bucket = NodeId.Resource("customer_data");

    /// <summary>Package → code → task → role → bucket, with one inferred join in the middle.</summary>
    private static GraphFixture Flagship() => new GraphFixture()
        .Node(NodeType.Pkg, "newtonsoft.json")
        .Node(NodeType.Code, "orderapp")
        .Node(NodeType.Task, "order_task")
        .Node(NodeType.IamRole, "order_task_role")
        .Node(NodeType.Resource, "customer_data")
        .Edge(Package, Code, "used-by")
        .Edge(Code, Task, "deployed-as", Confidence.Inferred)
        .Edge(Task, Role, "assumes")
        .Edge(Role, Bucket, "can-access")
        .Finding(Package, severity: 4, "CVE-2015-6420 deserialization gadget")
        .Finding(Code, severity: 4, "CWE-502 unsafe deserialization");

    private static IReadOnlyList<CandidateChain> Candidates(GraphFixture graph) =>
        Traverser.Traverse(graph.Nodes, graph.Edges, graph.Decoration());

    // ---- The shape the acceptance box names --------------------------------------------------

    [Fact]
    public void A_chain_is_handed_over_carrying_its_nodes_its_findings_and_its_confidence()
    {
        var graph = Flagship();

        var handoff = AttackGraphHandoff.From(GraphFixture.Tenant, GraphFixture.Job, Candidates(graph));

        var flagship = Assert.Single(
            handoff.Candidates,
            c => c.Hops.Select(h => h.Node.NodeKey).SequenceEqual([Package, Code, Task, Role, Bucket]));

        // Nodes: the whole GraphNode travels, not a node key the debate would have to re-look-up,
        // and each one once however many chains cross it.
        Assert.All(flagship.Hops, h => Assert.NotNull(h.Node));
        Assert.Equal(
            new[] { Package, Code, Task, Role, Bucket }.Order(),
            handoff.Nodes.Select(n => n.NodeKey).Order());

        // First appearance wins, so the highest-priority path's seed leads the list.
        Assert.Equal(handoff.Candidates[0].Seed.Node.NodeKey, handoff.Nodes[0].NodeKey);

        // Findings: the ones decorating the path, most severe first, de-duplicated across chains.
        Assert.Equal(graph.Findings.Count, handoff.Findings.Count);
        Assert.All(handoff.Findings, f => Assert.Contains(f, graph.Findings));

        // Confidence: the weakest join, which is the inferred code→task hop, not the three
        // certain ones around it (AID-01 §3.3).
        Assert.Equal(Confidence.Inferred, flagship.MinConfidence);
        Assert.Equal(Confidence.Inferred, handoff.WeakestConfidence);
    }

    [Fact]
    public void Every_hop_arrives_with_its_technique_and_evidence_slots_empty()
    {
        var handoff = AttackGraphHandoff.From(GraphFixture.Tenant, GraphFixture.Job, Candidates(Flagship()));

        Assert.NotEmpty(handoff.Candidates);

        // The traverser knows the path is walkable, not what technique walks it. Filling either
        // slot here would put a graph-stage guess where a cited agent claim belongs.
        Assert.All(handoff.Candidates.SelectMany(c => c.Hops), hop =>
        {
            Assert.Equal(string.Empty, hop.TechniqueId);
            Assert.Empty(hop.Evidence);
        });
    }

    [Fact]
    public void Candidates_are_handed_over_in_priority_order_however_they_arrive()
    {
        var shuffled = Candidates(Flagship()).OrderByDescending(c => c.Priority).ToList();
        Assert.True(shuffled.Count > 1, "the flagship graph must produce more than one candidate");

        var handoff = AttackGraphHandoff.From(GraphFixture.Tenant, GraphFixture.Job, shuffled);

        // The Red agent reads this list top-down under a turn cap, so the traverser's ranking is
        // what decides which chains get reasoned about at all.
        Assert.Equal(
            handoff.Candidates.Select(c => c.Priority).Order(),
            handoff.Candidates.Select(c => c.Priority));
    }

    [Fact]
    public void A_traversal_that_found_nothing_hands_over_an_empty_handoff_rather_than_none()
    {
        // A bundle with no Terraform and no lock file has no edges, so no path crosses a layer.
        // "No candidates" is a fact the later stages should read, not a null they should guard.
        var handoff = AttackGraphHandoff.From(GraphFixture.Tenant, GraphFixture.Job, []);

        Assert.True(handoff.IsEmpty);
        Assert.Empty(handoff.Candidates);
        Assert.Empty(handoff.Nodes);
        Assert.Empty(handoff.Findings);
    }

    // ---- Static resource graph, asserted attack graph, one direction between them -------------

    [Fact]
    public void A_candidate_that_already_names_a_technique_is_refused()
    {
        var candidates = Candidates(Flagship());
        var asserted = WithFirstHop(candidates[0], candidates[0].Seed with { TechniqueId = "T1059" });

        var ex = Assert.Throws<InvalidOperationException>(
            () => AttackGraphHandoff.From(GraphFixture.Tenant, GraphFixture.Job, [asserted]));

        Assert.Contains("asserted technique", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_candidate_that_already_carries_evidence_is_refused()
    {
        // Same failure as the technique, and the one that would be hardest to spot afterwards: an
        // evidence string invented by the graph stage reads in a report exactly like a citation.
        var candidates = Candidates(Flagship());
        var asserted = WithFirstHop(
            candidates[0], candidates[0].Seed with { Evidence = ["the traverser thought so"] });

        Assert.Throws<InvalidOperationException>(
            () => AttackGraphHandoff.From(GraphFixture.Tenant, GraphFixture.Job, [asserted]));
    }

    [Fact]
    public void A_candidate_whose_nodes_belong_to_another_scan_is_refused()
    {
        // The one defect here that cannot be walked back: a handoff assembled across scans puts
        // one tenant's resources into another tenant's prompt.
        var candidates = Candidates(Flagship());

        var ex = Assert.Throws<InvalidOperationException>(
            () => AttackGraphHandoff.From(Guid.NewGuid(), GraphFixture.Job, candidates));

        Assert.Contains("belongs to tenant", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The same candidate with its seed hop replaced, so a test can dirty one slot.</summary>
    private static CandidateChain WithFirstHop(CandidateChain chain, CandidateHop hop) =>
        chain with { Hops = [hop, .. chain.Hops.Skip(1)] };
}

using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Reporting;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Application.Features.Scan.ThinSlice;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Integration.Tests.Handoff;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// SEC-21 through the real pipeline: the candidate chains SEC-20 found reach the next stage
/// unaltered, and they are what retrieval spends its budget on.
/// </summary>
/// <remarks>
/// The unit tests pin the handoff's shape and the query's wording. This file answers the question
/// neither can: whether the wiring actually carries them. A handoff type that is correct and never
/// populated is the same outcome as not having one, and it fails silently — the debate simply
/// reasons about nothing in particular.
/// </remarks>
public class AttackGraphHandoffWiringTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private static ThinSlicePipeline Build(IKnowledgeRetriever retriever) =>
        new(new GraphSeeder(),
            new RetrievalQueryBuilder(),
            retriever,
            new ScanBriefRenderer(),
            new CapturingDebate(),
            new ReportBuilder(),
            new FakeScanRetentionPolicy(),
            NullLogger<ThinSlicePipeline>.Instance);

    private static GraphNode Node(NodeType type, string identifier, Layer layer) =>
        GraphNode.Create(Tenant, Job, type, identifier, layer, isHot: true);

    private static Finding Finding(int severity, string nodeRef, string cwe, string message) => new()
    {
        Id = Guid.CreateVersion7(),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = "test",
        Layer = Layer.Code,
        Severity = severity,
        CweId = cwe,
        NodeRef = nodeRef,
        Message = message,
    };

    /// <summary>
    /// One two-hop candidate: a code node reached from nothing, leading to the crown-jewel bucket.
    /// Built the way <c>ExploitChainTraverser</c> builds one — real nodes, an edge on the second
    /// hop, findings attached, both slots empty.
    /// </summary>
    private static (IReadOnlyList<GraphNode> Nodes, CandidateChain Chain, Finding OnPath) Candidate(
        int severityOnPath)
    {
        var code = Node(NodeType.Code, "orderapp", Layer.Code);
        var bucket = Node(NodeType.Resource, "customer_data", Layer.Infra);
        code.Id = Guid.CreateVersion7();
        bucket.Id = Guid.CreateVersion7();

        var onPath = Finding(severityOnPath, code.NodeKey, "CWE-502", "Unsafe deserialization in OrderApp");

        var edge = new GraphEdge
        {
            Id = Guid.CreateVersion7(),
            TenantId = Tenant,
            ScanJobId = Job,
            FromNodeId = code.Id,
            ToNodeId = bucket.Id,
            Relation = "can-access",
            Seam = Seam.InfraSpine,
            Confidence = Confidence.Inferred,
            OrientedAttackDir = true,
        };

        var chain = new CandidateChain(
            [new CandidateHop(0, code, null, [onPath]), new CandidateHop(1, bucket, edge, [])],
            Confidence.Inferred,
            Priority: 1);

        return ([code, bucket], chain, onPath);
    }

    [Fact]
    public async Task The_pipeline_carries_the_candidates_on_with_their_slots_still_empty()
    {
        var (nodes, chain, onPath) = Candidate(severityOnPath: 4);
        var retriever = new CapturingRetriever();

        var result = await Build(retriever).RunAsync([onPath], Tenant, Job, nodes, [chain]);

        var handed = Assert.Single(result.Handoff.Candidates);

        Assert.Equal(Tenant, result.Handoff.TenantId);
        Assert.Equal(Job, result.Handoff.ScanJobId);
        Assert.Equal(Confidence.Inferred, result.Handoff.WeakestConfidence);
        Assert.Same(onPath, Assert.Single(result.Handoff.Findings));
        Assert.Equal(nodes.Select(n => n.NodeKey), result.Handoff.Nodes.Select(n => n.NodeKey));

        Assert.All(handed.Hops, hop =>
        {
            Assert.Equal(string.Empty, hop.TechniqueId);
            Assert.Empty(hop.Evidence);
        });
    }

    [Fact]
    public async Task A_run_with_no_candidates_still_produces_a_handoff()
    {
        // The walking skeleton's case: findings, nodes, no edges. The stage after this one must be
        // able to read "no paths were found" rather than having to tell a null apart from a claim.
        var result = await Build(new CapturingRetriever())
            .RunAsync([Finding(4, NodeId.Code("orderapp"), "CWE-502", "Unsafe deserialization")], Tenant, Job);

        Assert.True(result.Handoff.IsEmpty);
        Assert.Equal(Job, result.Handoff.ScanJobId);
    }

    [Fact]
    public async Task Retrieval_spends_its_budget_on_the_findings_that_are_on_a_path()
    {
        // A low-severity finding two hops from the crown jewel is worth more to the debate than a
        // severe one sitting on nothing, because the debate reasons inside the candidates. Without
        // the handoff ordering the seeds, the severity-4 noise below fills the budget and the one
        // finding the debate can actually use retrieves nothing.
        var (nodes, chain, onPath) = Candidate(severityOnPath: 1);

        var noise = Enumerable.Range(1, ThinSlicePipeline.RetrievalSeedCount)
            .Select(i => Finding(4, NodeId.Code($"unrelated{i}"), $"CWE-{i}00", $"Unrelated weakness {i}"))
            .ToList();

        var retriever = new CapturingRetriever();

        await Build(retriever).RunAsync([.. noise, onPath], Tenant, Job, nodes, [chain]);

        // The seed budget is per agent, and since SEC-23 there are two of them — so the budget is
        // spent twice over, once against offense and once against defense. What matters is that
        // the on-path finding is inside it both times, not that the total is unchanged.
        Assert.Equal(
            ThinSlicePipeline.RetrievalSeedCount * ThinSlicePipeline.RetrievingRoles.Count,
            retriever.Calls.Count);

        Assert.Contains(retriever.Calls, c => c.Query.StartsWith("CWE-502", StringComparison.Ordinal));

        foreach (var collection in new[] { "offense", "defense" })
        {
            Assert.Contains(retriever.Calls,
                c => c.Collection == collection && c.Query.StartsWith("CWE-502", StringComparison.Ordinal));
        }
    }
}

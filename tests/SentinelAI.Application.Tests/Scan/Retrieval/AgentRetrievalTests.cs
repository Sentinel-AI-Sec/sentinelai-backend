using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// SEC-23: one shared corpus, split by role and never by tool.
/// </summary>
public class AgentRetrievalTests
{
    // ---- acceptance criterion 1 --------------------------------------------------------------
    // "Given a finding, when the Red agent retrieves, then it hits the offense collection; the
    //  Blue agent hits defense."

    [Fact]
    public void Red_reads_offense_and_blue_reads_defense()
    {
        Assert.Equal(KnowledgeCollection.Offense, AgentRetrieval.CollectionFor(AgentRole.Red));
        Assert.Equal(KnowledgeCollection.Defense, AgentRetrieval.CollectionFor(AgentRole.Blue));
    }

    [Fact]
    public void Red_asks_how_an_attack_works_and_blue_how_it_is_remediated()
    {
        Assert.Equal(RetrievalIntent.HowAnAttackerWould, AgentRetrieval.IntentFor(AgentRole.Red));
        Assert.Equal(RetrievalIntent.HowToFix, AgentRetrieval.IntentFor(AgentRole.Blue));
    }

    /// <summary>
    /// The split has to survive into the actual query, not just the collection choice. An
    /// unfiltered defense query still returns CVE descriptions, so "Blue reads defense" alone
    /// would not be enough.
    /// </summary>
    [Fact]
    public void Each_role_carries_the_mandatory_filter_that_belongs_to_its_question()
    {
        var red = AgentRetrieval.IntentFor(AgentRole.Red)!.Value.ToQuery("unsafe deserialization");
        var blue = AgentRetrieval.IntentFor(AgentRole.Blue)!.Value.ToQuery("unsafe deserialization");

        Assert.True(red.IsFiltered);
        Assert.True(blue.IsFiltered);

        Assert.Equal([KnowledgeSource.Attack, KnowledgeSource.Capec], red.Sources);
        Assert.Equal([KnowledgeContentType.Mitigation], blue.ContentTypes);
    }

    /// <summary>
    /// Neither reasons about new knowledge — the Orchestrator summarises what it was handed and
    /// the Reporter adjudicates a transcript whose claims are already cited.
    /// </summary>
    [Theory]
    [InlineData(AgentRole.Orchestrator)]
    [InlineData(AgentRole.Reporter)]
    public void The_agents_that_do_not_reason_over_the_corpus_retrieve_nothing(AgentRole role)
    {
        Assert.Null(AgentRetrieval.IntentFor(role));
        Assert.Null(AgentRetrieval.CollectionFor(role));
        Assert.False(role.Retrieves());
    }

    [Fact]
    public void Exactly_two_agents_retrieve()
    {
        Assert.Equal([AgentRole.Red, AgentRole.Blue], AgentRetrieval.RetrievingRoles);
    }

    [Fact]
    public void Every_role_has_a_decided_answer_rather_than_falling_through()
    {
        // No role may throw: a new agent added to the enum must force a decision here, and this
        // is what turns "we forgot" into a failing test rather than a runtime surprise.
        foreach (var role in Enum.GetValues<AgentRole>())
            _ = AgentRetrieval.IntentFor(role);
    }

    // ---- acceptance criterion 2 ----------------------------------------------------------------
    // "Given any tool's finding, when retrieved, then it resolves into the shared corpus (no
    //  per-tool index)."

    /// <summary>
    /// The same weakness reported by four different scanners retrieves the same knowledge. What
    /// decides the collection is who is asking, never who found it.
    /// </summary>
    [Fact]
    public async Task Every_tool_resolves_into_the_same_shared_corpus()
    {
        string[] tools = ["SecurityCodeScan", "Checkov", "Trivy", "osv-scanner"];
        var chunksByTool = new Dictionary<string, IReadOnlyList<string>>();
        var collectionsAsked = new List<KnowledgeCollection>();

        foreach (var tool in tools)
        {
            var corpus = new FakeCorpus();
            var service = new KnowledgeRetrievalService(
                new RetrievalQueryBuilder(), corpus, new FakeEmbedder(),
                NullLogger<KnowledgeRetrievalService>.Instance);

            var result = await service.RetrieveAsync(
                SameWeaknessFrom(tool), AgentRetrieval.IntentFor(AgentRole.Red)!.Value);

            chunksByTool[tool] = [.. result.Chunks.Select(c => c.ChunkId)];
            collectionsAsked.AddRange(corpus.ExactLookups.Select(l => l.Collection));
        }

        // Identical knowledge for all four tools — no per-tool index anywhere.
        var expected = chunksByTool[tools[0]];
        Assert.All(chunksByTool.Values, chunks => Assert.Equal(expected, chunks));
        Assert.NotEmpty(expected);

        // And every one of them asked the same collection, chosen by the role.
        Assert.All(collectionsAsked, c => Assert.Equal(KnowledgeCollection.Offense, c));
    }

    /// <summary>
    /// The counterpart: one tool's finding, asked by both agents, reaches both halves of the
    /// corpus. The split is by role, and it is the only split.
    /// </summary>
    [Fact]
    public async Task One_finding_asked_by_both_agents_reaches_both_halves()
    {
        var asked = new List<KnowledgeCollection>();

        foreach (var role in AgentRetrieval.RetrievingRoles)
        {
            var corpus = new FakeCorpus();
            var service = new KnowledgeRetrievalService(
                new RetrievalQueryBuilder(), corpus, new FakeEmbedder(),
                NullLogger<KnowledgeRetrievalService>.Instance);

            await service.RetrieveAsync(SameWeaknessFrom("Checkov"), AgentRetrieval.IntentFor(role)!.Value);

            asked.AddRange(corpus.ExactLookups.Select(l => l.Collection));
        }

        Assert.Contains(KnowledgeCollection.Offense, asked);
        Assert.Contains(KnowledgeCollection.Defense, asked);
    }

    /// <summary>The same weakness, differing only in which scanner reported it.</summary>
    private static Finding SameWeaknessFrom(string tool) => new()
    {
        Id = Guid.CreateVersion7(),
        SourceTool = tool,
        Layer = Layer.Code,
        Severity = 3,
        CweId = "CWE-502",
        NodeRef = NodeId.Code("orderapp"),
        Message = "Unsafe deserialization of untrusted data.",
    };
}

using Microsoft.Extensions.Configuration;
using SentinelAI.Api.Controllers;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// A whole debate, from the brief the agents read to the JSON shape the transcript panel
/// renders.
/// </summary>
/// <remarks>
/// <para>
/// The unit tests for <see cref="TurnPresenter"/> feed it turns written by hand. This one feeds
/// it turns the agents actually produced under their real instructions, against the real stub
/// brief, through the real DTO. That closes the gap those tests cannot: an instruction change
/// that quietly stops producing parseable hop lines passes every unit test and ships a
/// transcript with no structure in it, because the presenter is doing exactly what it was told
/// on text nobody checked.
/// </para>
/// <para>
/// It runs on the Scripted provider, so it is offline, deterministic and free — but the canned
/// turns are written in the shape each role's <c>Instructions</c> mandate, which is precisely
/// what makes them a fair sample of one.
/// </para>
/// </remarks>
public class TranscriptPresentationTests
{
    private static async Task<DebateResponse> RunAsync()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SentinelAI:Models:Provider"] = "Scripted",
            })
            .Build();

        var models = ModelOptionsLoader.Load(configuration);
        var workflow = DebateWorkflow.Build(new ChatClientFactory(models), new DebateOptions());

        var brief = ScanBrief.Stub("presentation-scan");
        var result = await new DebateRunner(workflow).RunAsync(brief);

        Assert.NotNull(result.Audit);
        return DebateResponse.From(brief, result.Audit!);
    }

    private static DebateResponse.TurnView TurnOf(DebateResponse response, AgentRole role) =>
        Assert.Single(response.Transcript.Where(t => t.Role == role.ToString()));

    [Fact]
    public async Task Reds_chain_arrives_as_hops_named_by_the_graphs_own_node_keys()
    {
        var red = TurnOf(await RunAsync(), AgentRole.Red);

        Assert.Equal(4, red.Display.Hops.Count);

        var first = red.Display.Hops[0];
        Assert.Equal("N1", first.From);
        Assert.Equal("pkg:commons-collections:3.2.1", first.FromLabel);
        Assert.Equal("code:appdatahandler.deserialize()", first.ToLabel);
        Assert.Equal("used-by", first.Relation);
        Assert.NotNull(first.Evidence);
    }

    /// <summary>
    /// Every hop the agents assert on the stub brief is a real edge in it, so a mismatch here is
    /// the presenter or the fixture drifting — not the debate being wrong.
    /// </summary>
    [Fact]
    public async Task Every_asserted_hop_matches_a_real_edge_in_the_brief()
    {
        var response = await RunAsync();

        Assert.All(
            response.Transcript.SelectMany(t => t.Display.Hops),
            hop => Assert.Equal(TurnPresenter.HopGraphStatus.Confirmed, hop.GraphStatus));
    }

    /// <summary>
    /// Blue's per-hop vocabulary has to survive the round trip, including the one hop it could
    /// not settle — which is the whole reason the verdict is four-valued.
    /// </summary>
    [Fact]
    public async Task Blues_verdicts_land_on_the_hops_they_were_written_about()
    {
        var blue = TurnOf(await RunAsync(), AgentRole.Blue);

        Assert.Equal("CHAIN_HOLDS", blue.Display.Verdict);
        Assert.Equal(
            [
                HopVerdict.Confirmed.ToString(),
                HopVerdict.Unresolved.ToString(),
                HopVerdict.Confirmed.ToString(),
                HopVerdict.Confirmed.ToString(),
            ],
            blue.Display.Hops.Select(h => h.Verdict));
    }

    /// <summary>
    /// Only Blue gives a closing verdict. A verdict appearing on another agent's turn would mean
    /// the presenter had started reading one out of prose.
    /// </summary>
    [Fact]
    public async Task No_agent_but_blue_reports_a_closing_verdict()
    {
        var response = await RunAsync();

        Assert.All(
            response.Transcript.Where(t => t.Role != AgentRole.Blue.ToString()),
            t => Assert.Null(t.Display.Verdict));
    }

    [Fact]
    public async Task The_reporters_grading_arrives_as_labelled_fields()
    {
        var reporter = TurnOf(await RunAsync(), AgentRole.Reporter);

        Assert.Equal(
            ["CHAIN", "SEVERITY", "CONFIDENCE", "IMPACT", "EVIDENCE", "NEXT"],
            reporter.Display.Facts.Select(f => f.Label));
    }

    /// <summary>
    /// The whole point of the change: no turn reaches the screen as an unstructured blob.
    /// </summary>
    [Fact]
    public async Task No_turn_arrives_without_something_to_render()
    {
        var response = await RunAsync();

        Assert.NotEmpty(response.Transcript);
        Assert.All(response.Transcript, t => Assert.False(t.Display.IsEmpty));
    }

    /// <summary>
    /// The structure is a reading of the turn, and a reading nobody can check against the
    /// original is one they have to take on faith — so the text is always sent too.
    /// </summary>
    [Fact]
    public async Task Every_turn_still_carries_the_text_it_was_read_from()
    {
        var response = await RunAsync();

        Assert.All(response.Transcript, t => Assert.False(string.IsNullOrWhiteSpace(t.Content)));
        Assert.All(
            response.Transcript.SelectMany(t => t.Display.Hops),
            hop => Assert.Contains(hop.From, hop.Text, StringComparison.Ordinal));
    }
}

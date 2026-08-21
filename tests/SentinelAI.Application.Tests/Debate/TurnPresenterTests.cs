using SentinelAI.Application.Debate;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Tests.Debate;

/// <summary>
/// Reading a turn into the structure the transcript panel renders.
/// </summary>
/// <remarks>
/// The presenter has exactly one job the rest of the system does not already do — arranging
/// facts that were recovered elsewhere — so these tests are mostly about what it declines to
/// arrange. A hop it invents, a verdict it defaults, or a note it silently swallows is worse
/// than an unstructured turn, because the raw text is always rendered beside it and a reader
/// comparing the two would be reading a contradiction.
/// </remarks>
public class TurnPresenterTests
{
    /// <summary>The brief in the shape <c>ScanBriefRenderer</c> writes it.</summary>
    private const string Brief =
        """
        RESOURCE GRAPH

        Nodes: N1=pkg:newtonsoft.json | N2=code:orderapp | N3=task:ecs-task/api | N4=s3:crown-jewels

        Edges (these are the only ones that exist — do not infer any other):
          N1 --used-by--> N2 (certain)
          N2 --deployed-as--> N3 (inferred)
          N3 --can-access--> N4 (certain)

        Knowledge retrieved for Red (offense):
          - ATT&CK T1078 — Valid Accounts.
        """;

    private static DebateTurn Turn(AgentRole role, string content, bool converged = false,
        bool verdictReadable = true) =>
        new()
        {
            Role = role,
            Round = 1,
            Content = content,
            Converged = converged,
            VerdictReadable = verdictReadable,
        };

    [Fact]
    public void Reads_a_hop_line_into_its_parts()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Red,
            "HOP 1: N1 -> used-by -> N2 | T1078 | packages.lock.json pins 12.0.1"));

        var hop = Assert.Single(display.Hops);
        Assert.Equal(1, hop.Order);
        Assert.Equal("N1", hop.From);
        Assert.Equal("N2", hop.To);
        Assert.Equal("used-by", hop.Relation);
        Assert.Equal("T1078", hop.Technique);
        Assert.Equal("packages.lock.json pins 12.0.1", hop.Evidence);
    }

    /// <summary>
    /// The node names come from the brief, never from the agent's own inline annotation — that
    /// claim is checked separately by <c>EdgeAssertionValidator.ValidateNodeLabels</c>, and
    /// echoing it here would launder a fabricated label into the answer.
    /// </summary>
    [Fact]
    public void Labels_hops_with_the_briefs_node_keys_not_the_agents_claim()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Red, "HOP 1: N1:pkg:something-else -> used-by -> N2 | none | see F1"));

        var hop = Assert.Single(display.Hops);
        Assert.Equal("pkg:newtonsoft.json", hop.FromLabel);
        Assert.Equal("code:orderapp", hop.ToLabel);
    }

    [Fact]
    public void Carries_blues_verdict_onto_the_hop_it_was_written_about()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Blue,
            """
            HOP 1: N1 -> N2 | CONFIRMED | the lock file names it
            HOP 2: N2 -> N3 | UNRESOLVED | the image is joined by tag, not digest
            VERDICT: CHAIN_HOLDS
            """,
            converged: true));

        Assert.Equal(HopVerdict.Confirmed.ToString(), display.Hops[0].Verdict);
        Assert.Equal(HopVerdict.Unresolved.ToString(), display.Hops[1].Verdict);
        Assert.Equal("CHAIN_HOLDS", display.Verdict);
    }

    /// <summary>
    /// Silence is not a verdict. A hop Blue skipped must arrive as
    /// <see cref="HopVerdict.Unattributed"/>, which the UI is required to render as "no
    /// judgement" — never as a pass.
    /// </summary>
    [Fact]
    public void Leaves_a_hop_blue_said_nothing_about_unattributed()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Red, "HOP 1: N1 -> used-by -> N2 | none | see F1"));

        Assert.Equal(HopVerdict.Unattributed.ToString(), Assert.Single(display.Hops).Verdict);
    }

    /// <summary>
    /// The deterministic check is the only thing on the hop that is not a model's word, so a
    /// reversed edge has to survive into the presentation rather than being smoothed over.
    /// </summary>
    [Fact]
    public void Reports_a_reversed_edge_as_reversed()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Red, "HOP 1: N2 -> used-by -> N1 | none | see F1"));

        Assert.Equal(TurnPresenter.HopGraphStatus.Reversed, Assert.Single(display.Hops).GraphStatus);
    }

    [Fact]
    public void Reports_an_edge_the_brief_never_listed_as_unrecognized()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Red, "HOP 1: N1 -> reaches -> N4 | none | see F1"));

        Assert.Equal(TurnPresenter.HopGraphStatus.Unrecognized, Assert.Single(display.Hops).GraphStatus);
    }

    /// <summary>
    /// The same refusal <c>HopVerdictReader</c> makes: one verdict cannot be divided between two
    /// hops, so a line naming both is prose, not a hop.
    /// </summary>
    [Fact]
    public void Does_not_read_a_line_naming_two_hops_as_a_hop()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Blue, "Hops N1 -> N2 and N2 -> N3 are both CONFIRMED."));

        Assert.Empty(display.Hops);
    }

    [Fact]
    public void Splits_labelled_lines_into_fields()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Reporter,
            """
            CHAIN: N1 -> N2 -> N3 -> N4
            SEVERITY: high — the chain ends at the crown jewel
            NEXT: record the image digest
            """));

        Assert.Equal(["CHAIN", "SEVERITY", "NEXT"], display.Facts.Select(f => f.Label));
        Assert.Equal("record the image digest", display.Facts[2].Value);
    }

    /// <summary>
    /// A multi-hop CHAIN line names four hops, so it is not a hop line — it is the labelled
    /// summary of them, and must not be double-counted as a fifth hop.
    /// </summary>
    [Fact]
    public void Treats_a_whole_chain_line_as_a_fact_not_a_hop()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Reporter, "CHAIN: N1 -> N2 -> N3 -> N4"));

        Assert.Empty(display.Hops);
        Assert.Equal("CHAIN", Assert.Single(display.Facts).Label);
    }

    /// <summary>
    /// The agents name node pairs inside fields constantly — a weakest join, a summary of the
    /// path — and none of those is a hop being asserted. Reading one as a hop invents an
    /// assertion, then hangs a verdict and an edge check on it.
    /// </summary>
    [Fact]
    public void Does_not_read_a_node_pair_inside_a_labelled_field_as_a_hop()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Reporter, "CONFIDENCE: unresolved — the weakest join is N1 -> N2"));

        Assert.Empty(display.Hops);
        Assert.Equal("CONFIDENCE", Assert.Single(display.Facts).Label);
    }

    /// <summary>
    /// Red is asked to write <c>none</c> where the brief grounds no technique, which is right —
    /// but it is an empty field, not the first word of the evidence.
    /// </summary>
    [Fact]
    public void Drops_an_empty_technique_field_from_the_evidence()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Red, "HOP 1: N1 -> used-by -> N2 | none | packages.lock.json pins 12.0.1"));

        Assert.Equal("packages.lock.json pins 12.0.1", Assert.Single(display.Hops).Evidence);
    }

    /// <summary>
    /// A sentence with a colon in it is not a field. Only the upper-case labels the agents are
    /// instructed to write are promoted; everything else stays prose.
    /// </summary>
    [Fact]
    public void Does_not_promote_ordinary_prose_containing_a_colon()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Reporter, "Note: the image tag is mutable and was not recorded."));

        Assert.Empty(display.Facts);
        Assert.Equal("Note: the image tag is mutable and was not recorded.", display.Headline);
    }

    /// <summary>
    /// Blue's verdict is the one the workflow acted on, so an unreadable one is reported as
    /// unreadable rather than quietly reading as a break.
    /// </summary>
    [Fact]
    public void Reports_an_unreadable_verdict_as_unreadable()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Blue, "I was unable to finish checking", verdictReadable: false));

        Assert.Equal(TurnPresenter.VerdictUnreadable, display.Verdict);
    }

    [Fact]
    public void Only_blue_reports_a_closing_verdict()
    {
        foreach (var role in new[] { AgentRole.Red, AgentRole.Reporter, AgentRole.Orchestrator })
            Assert.Null(TurnPresenter.Present(Brief, Turn(role, "CHAIN: N1 -> N2")).Verdict);
    }

    /// <summary>
    /// Prose the presenter cannot structure is the normal case for a model that ignored its
    /// instructions, and the caller has to be able to tell — it renders the raw turn instead.
    /// </summary>
    [Fact]
    public void Reports_an_unstructurable_turn_as_empty()
    {
        Assert.True(TurnPresenter.Present(Brief, Turn(AgentRole.Red, "   ")).IsEmpty);
    }

    [Fact]
    public void Keeps_the_whole_line_beside_every_hop_it_read()
    {
        const string line = "HOP 1: N1 -> used-by -> N2 | T1078 | packages.lock.json pins 12.0.1";
        var display = TurnPresenter.Present(Brief, Turn(AgentRole.Red, line));

        Assert.Equal(line, Assert.Single(display.Hops).Text);
    }

    /// <summary>
    /// A model that answers in markdown must produce the same reading as one that does not —
    /// otherwise the structure appears and disappears with the provider's house style.
    /// </summary>
    [Fact]
    public void Reads_a_hop_the_model_wrapped_in_markdown()
    {
        var display = TurnPresenter.Present(Brief, Turn(
            AgentRole.Red,
            """
            <think>Let me look at the edges first.</think>
            ### Chain
            - **HOP 1:** N1 -> used-by -> N2 | T1078 | `packages.lock.json` pins 12.0.1
            """));

        var hop = Assert.Single(display.Hops);
        Assert.Equal("N1", hop.From);
        Assert.Equal("T1078", hop.Technique);
        Assert.DoesNotContain("think", hop.Text, StringComparison.OrdinalIgnoreCase);
    }
}

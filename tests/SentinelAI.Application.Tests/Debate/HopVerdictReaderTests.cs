using SentinelAI.Application.Debate;
using SentinelAI.Domain.Enums;

namespace SentinelAI.Application.Tests.Debate;

/// <summary>
/// Audit 42-A: reading Blue's per-hop verdict and Red's ATT&amp;CK id out of the debate
/// transcript.
/// </summary>
/// <remarks>
/// The cases that matter here are the refusals. Anything this reader gets wrong is written into
/// a hop row and served to the dashboard as fact, so every ambiguity below has to come back as
/// "no answer" rather than as the likeliest answer.
/// </remarks>
public class HopVerdictReaderTests
{
    /// <summary>
    /// The brief in the shape <c>ScanBriefRenderer</c> writes it — which is where the
    /// <c>N&lt;n&gt;</c> labels get their meaning, and the only reason the transcript can be
    /// joined to anything.
    /// </summary>
    private const string Brief =
        """
        RESOURCE GRAPH

        Nodes: N1=pkg:newtonsoft.json | N2=code:orderapp | N3=task:ecs-task/api | N4=s3:crown-jewels

        Edges (these are the only ones that exist — do not infer any other):
          N1 --used-by--> N2 (certain)
          N2 --deployed-as--> N3 (inferred)
          N3 --can-access--> N4 (certain)

        Knowledge retrieved for Red (offense):
          - ATT&CK T1078 — Valid Accounts. An over-permissive IAM policy lets a compromised
            workload read the bucket.
          - ATT&CK T1190 — Exploit Public-Facing Application.
        """;

    private static HopRef Hop(string from, string to) => new(from, to);

    private static readonly HopRef PkgToCode = Hop("pkg:newtonsoft.json", "code:orderapp");
    private static readonly HopRef CodeToTask = Hop("code:orderapp", "task:ecs-task/api");
    private static readonly HopRef TaskToBucket = Hop("task:ecs-task/api", "s3:crown-jewels");

    // ---- Blue's verdicts ------------------------------------------------------------------

    /// <summary>
    /// The shape Blue's instructions ask for, and the shape a live turn produced: one line per
    /// hop, naming the two nodes and ending in one of the three tokens.
    /// </summary>
    [Fact]
    public void Each_hop_line_is_read_as_the_verdict_it_ends_in()
    {
        const string blue =
            """
            N1 -> used-by -> N2: CONFIRMED, packages.lock.json pins the vulnerable version.
            N2 -> deployed-as -> N3: UNRESOLVED, the image-name join has no digest.
            N3 -> can-access -> N4: REFUTED, the role's policy carries an explicit Deny.
            VERDICT: CHAIN_BROKEN
            """;

        var verdicts = HopVerdictReader.ReadVerdicts(Brief, blue);

        Assert.Equal(HopVerdict.Confirmed, verdicts[PkgToCode]);
        Assert.Equal(HopVerdict.Unresolved, verdicts[CodeToTask]);
        Assert.Equal(HopVerdict.Refuted, verdicts[TaskToBucket]);
    }

    /// <summary>
    /// A hop Blue simply did not write a line for gets no entry — the caller turns that into
    /// <see cref="HopVerdict.Unattributed"/>, never into a refutation.
    /// </summary>
    [Fact]
    public void A_hop_blue_never_mentioned_is_absent_rather_than_negative()
    {
        var verdicts = HopVerdictReader.ReadVerdicts(Brief, "N1 -> used-by -> N2: CONFIRMED.");

        Assert.True(verdicts.ContainsKey(PkgToCode));
        Assert.False(verdicts.ContainsKey(CodeToTask));
        Assert.False(verdicts.ContainsKey(TaskToBucket));
    }

    /// <summary>
    /// The worst thing this parser could do. "NOT CONFIRMED" contains the token that means the
    /// opposite of what the sentence says.
    /// </summary>
    [Theory]
    [InlineData("N1 -> used-by -> N2: NOT CONFIRMED — the lock file does not pin it.")]
    [InlineData("N1 -> used-by -> N2: I cannot say CONFIRMED here.")]
    [InlineData("N1 -> used-by -> N2 is not REFUTED, merely unproven.")]
    public void A_negated_token_yields_no_verdict_at_all(string line)
    {
        Assert.Empty(HopVerdictReader.ReadVerdicts(Brief, line));
    }

    /// <summary>
    /// Blue's own instructions contain the sentence "UNRESOLVED is not REFUTED", and a model
    /// that echoes the distinction while judging a hop has written two verdicts on one line.
    /// Neither of them can be the answer.
    /// </summary>
    [Fact]
    public void A_line_naming_two_verdicts_settles_nothing()
    {
        Assert.Empty(HopVerdictReader.ReadVerdicts(
            Brief, "N1 -> used-by -> N2: UNRESOLVED, which is not REFUTED."));
    }

    /// <summary>A verdict covering two hops cannot be divided between them.</summary>
    [Fact]
    public void A_line_naming_two_hops_is_not_attributed_to_either()
    {
        Assert.Empty(HopVerdictReader.ReadVerdicts(
            Brief, "N1 -> used-by -> N2 and N3 -> can-access -> N4: CONFIRMED."));
    }

    /// <summary>
    /// "hop 2 is confirmed" is the shape of the offline canned turn and of any model that
    /// numbers hops instead of naming them. There is no way to know which edge hop 2 is
    /// without re-deriving Red's chain from prose, so this reads nothing.
    /// </summary>
    [Fact]
    public void A_verdict_with_no_node_reference_anchors_to_nothing()
    {
        Assert.Empty(HopVerdictReader.ReadVerdicts(
            Brief, "hop 1 CONFIRMED against packages.lock.json. hop 2 CONFIRMED."));
    }

    /// <summary>Lower case is discussion, upper case is the verdict Blue was asked for.</summary>
    [Fact]
    public void Lower_case_prose_is_not_a_verdict()
    {
        Assert.Empty(HopVerdictReader.ReadVerdicts(
            Brief, "N1 -> used-by -> N2 looks confirmed to me."));
    }

    /// <summary>The word bound is what keeps UNCONFIRMED from reading as CONFIRMED.</summary>
    [Fact]
    public void Unconfirmed_is_not_confirmed()
    {
        Assert.Empty(HopVerdictReader.ReadVerdicts(Brief, "N1 -> used-by -> N2: UNCONFIRMED."));
    }

    /// <summary>
    /// Two lines about one hop that disagree retract it. Taking the first, the last or the
    /// worst would each be this class inventing a policy for text neither agent meant that way.
    /// </summary>
    [Fact]
    public void Two_contradictory_lines_about_one_hop_leave_it_unattributed()
    {
        const string blue =
            """
            N1 -> used-by -> N2: CONFIRMED.
            On reflection, N1 -> used-by -> N2: REFUTED.
            """;

        Assert.Empty(HopVerdictReader.ReadVerdicts(Brief, blue));
    }

    /// <summary>The same verdict twice is agreement, not contradiction.</summary>
    [Fact]
    public void The_same_verdict_restated_survives()
    {
        const string blue =
            """
            N1 -> used-by -> N2: CONFIRMED, the lock file pins it.
            To restate: N1 -> used-by -> N2: CONFIRMED.
            """;

        Assert.Equal(HopVerdict.Confirmed, HopVerdictReader.ReadVerdicts(Brief, blue)[PkgToCode]);
    }

    /// <summary>
    /// The stub resource graph writes its edges with a unicode arrow and the agents mirror the
    /// brief they were handed, so a turn answering one has to anchor too.
    /// </summary>
    [Fact]
    public void A_unicode_arrow_anchors_a_hop_the_same_way()
    {
        var verdicts = HopVerdictReader.ReadVerdicts(Brief, "N1 → used-by → N2: CONFIRMED.");

        Assert.Equal(HopVerdict.Confirmed, verdicts[PkgToCode]);
    }

    /// <summary>
    /// Two node numbers next to each other with no arrow between them are not a hop — the same
    /// rule <see cref="EdgeAssertionValidator"/> learned from a live Reporter turn whose comma
    /// listed a branch target rather than a hop.
    /// </summary>
    [Fact]
    public void Adjacent_node_references_with_no_arrow_are_not_a_hop()
    {
        Assert.Empty(HopVerdictReader.ReadVerdicts(Brief, "Checked N1, N2: CONFIRMED."));
    }

    /// <summary>A node index this brief never declared cannot be mapped to a node key.</summary>
    [Fact]
    public void A_node_the_brief_never_declared_is_ignored()
    {
        Assert.Empty(HopVerdictReader.ReadVerdicts(Brief, "N1 -> used-by -> N77: CONFIRMED."));
    }

    /// <summary>No brief means no meaning for N1, whatever the turn says.</summary>
    [Fact]
    public void Without_a_brief_nothing_is_readable()
    {
        Assert.Empty(HopVerdictReader.ReadVerdicts(string.Empty, "N1 -> used-by -> N2: CONFIRMED."));
        Assert.Empty(HopVerdictReader.ReadVerdicts(Brief, null));
    }

    // ---- Red's techniques -----------------------------------------------------------------

    [Fact]
    public void A_technique_id_the_brief_names_is_read_for_its_hop()
    {
        const string red = "N3 -> T1078 valid accounts -> N4: the task role can read the bucket.";

        Assert.Equal("T1078", HopVerdictReader.ReadTechniques(Brief, red)[TaskToBucket]);
    }

    /// <summary>
    /// An id from the model's own memory rather than from the brief it was given. There is
    /// nothing in this system that can check it, so it is dropped — the same stance
    /// <see cref="EdgeAssertionValidator"/> takes on an edge nobody listed.
    /// </summary>
    [Fact]
    public void An_id_the_brief_never_mentions_is_not_persisted()
    {
        Assert.Empty(HopVerdictReader.ReadTechniques(
            Brief, "N3 -> T1552 unsecured credentials -> N4."));
    }

    /// <summary>
    /// The brief said "Valid Accounts". <c>T1078.004</c> says "Cloud Accounts" — a sharper
    /// claim than the evidence supports, which is the whole failure mode 42-A is about.
    /// </summary>
    [Fact]
    public void A_sub_technique_is_not_grounded_by_its_parent_alone()
    {
        Assert.Empty(HopVerdictReader.ReadTechniques(Brief, "N3 -> T1078.004 -> N4."));
    }

    /// <summary>Two ids on one hop line cannot be split between them.</summary>
    [Fact]
    public void Two_ids_on_one_line_yield_none()
    {
        Assert.Empty(HopVerdictReader.ReadTechniques(Brief, "N3 -> T1078 or maybe T1190 -> N4."));
    }

    /// <summary>
    /// The pre-42-A live shape: the technique slot held the graph's own relation word. Nothing
    /// to read, and nothing invented to fill the gap.
    /// </summary>
    [Fact]
    public void A_hop_line_with_no_attack_id_yields_no_technique()
    {
        Assert.Empty(HopVerdictReader.ReadTechniques(
            Brief, "N3:task:ecs-task/api -> technique:can-access -> evidence:N4:s3:crown-jewels"));
    }

    /// <summary>
    /// A four-digit number is not an ATT&amp;CK id unless it is spelled like one; CVE years and
    /// port numbers are not techniques.
    /// </summary>
    [Fact]
    public void A_bare_number_is_not_a_technique()
    {
        Assert.Empty(HopVerdictReader.ReadTechniques(Brief, "N3 -> CVE-2015-6420 on port 1078 -> N4."));
    }
}

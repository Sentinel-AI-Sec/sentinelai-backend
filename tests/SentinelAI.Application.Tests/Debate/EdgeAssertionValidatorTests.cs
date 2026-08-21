using SentinelAI.Application.Debate;

namespace SentinelAI.Application.Tests.Debate;

/// <summary>
/// SEC-50: the mechanical fact-check on Red's asserted hops. Every case here is either a
/// minimal reproduction or the actual transcript from the live run that exposed the bug —
/// a live model asserted <c>N3 -&gt; assumes -&gt; N69</c> when the real edge runs the other
/// way, and Blue's own validation confirmed it anyway.
/// </summary>
public class EdgeAssertionValidatorTests
{
    private const string ThreeNodeBrief =
        """
        RESOURCE GRAPH

        Nodes: N1=code:orderapp | N2=iam_role:order_task_role | N3=s3:customer_data

        Edges (these are the only ones that exist — do not infer any other):
          N1 --deployed-as--> N2 (inferred)
          N2 --can-access--> N3 (certain)
        """;

    [Fact]
    public void A_correctly_asserted_hop_is_confirmed()
    {
        var findings = EdgeAssertionValidator.Validate(ThreeNodeBrief, "N1 -> deployed-as -> N2");

        var finding = Assert.Single(findings);
        Assert.Equal(EdgeAssertionValidator.HopStatus.Confirmed, finding.Status);
    }

    [Fact]
    public void A_reversed_hop_is_flagged_reversed_not_dropped()
    {
        // The real edge is N2 --can-access--> N3. Asserting it backwards is exactly what the
        // live run did with N3 -> assumes -> N69 (real edge: N69 --assumes--> N3).
        var findings = EdgeAssertionValidator.Validate(ThreeNodeBrief, "N3 -> can-access -> N2");

        var finding = Assert.Single(findings);
        Assert.Equal(EdgeAssertionValidator.HopStatus.Reversed, finding.Status);
        Assert.Contains("real edge runs N2 -> N3", finding.Describe());
    }

    [Fact]
    public void A_hop_with_no_edge_in_either_direction_is_unrecognized()
    {
        var findings = EdgeAssertionValidator.Validate(ThreeNodeBrief, "N1 -> can-access -> N3");

        var finding = Assert.Single(findings);
        Assert.Equal(EdgeAssertionValidator.HopStatus.Unrecognized, finding.Status);
    }

    [Fact]
    public void The_same_pair_asserted_twice_is_reported_once()
    {
        var findings = EdgeAssertionValidator.Validate(
            ThreeNodeBrief, "N1 -> deployed-as -> N2\nLater: N1 -> deployed-as -> N2 again.");

        Assert.Single(findings);
    }

    [Fact]
    public void A_self_reference_is_not_a_hop()
    {
        var findings = EdgeAssertionValidator.Validate(ThreeNodeBrief, "N1 -> N1 makes no sense.");

        Assert.Empty(findings);
    }

    /// <summary>
    /// A live regression the other direction: the Reporter wrote <c>N3 -&gt; N65, N66</c> —
    /// N3 branches to two targets, not a hop from N65 to N66. Pairing every consecutive token
    /// regardless of what separates them would flag an edge nobody asserted.
    /// </summary>
    [Fact]
    public void Two_node_references_separated_by_a_comma_not_an_arrow_are_not_a_hop()
    {
        var findings = EdgeAssertionValidator.Validate(ThreeNodeBrief, "Chain confirmed: N1 -> N2, N3");

        // N1->N2 is real and correctly directed; N2,N3 must not be read as an asserted N2->N3 hop.
        var finding = Assert.Single(findings);
        Assert.Equal("N1", finding.From);
        Assert.Equal("N2", finding.To);
        Assert.Equal(EdgeAssertionValidator.HopStatus.Confirmed, finding.Status);
    }

    [Fact]
    public void A_line_naming_only_one_node_asserts_nothing()
    {
        var findings = EdgeAssertionValidator.Validate(ThreeNodeBrief, "N1 is code:orderapp, the entry point.");

        Assert.Empty(findings);
    }

    [Fact]
    public void No_brief_or_no_text_yields_no_findings_rather_than_throwing()
    {
        Assert.Empty(EdgeAssertionValidator.Validate("", "N1 -> deployed-as -> N2"));
        Assert.Empty(EdgeAssertionValidator.Validate(ThreeNodeBrief, ""));
    }

    /// <summary>
    /// <c>ScanBrief.Stub</c> — the fixture behind the demo endpoint and every offline run —
    /// writes its edges with a unicode arrow rather than the <c>--relation--&gt;</c> form
    /// <c>ScanBriefRenderer</c> uses. Only the latter was ever matched, so this check found no
    /// real edges in that brief and returned nothing at all: not "the chain is clean", but no
    /// check having run on the one brief anybody demonstrates the product with.
    /// </summary>
    [Fact]
    public void The_unicode_arrow_edge_section_is_read_as_real_edges()
    {
        const string arrowBrief =
            """
            RESOURCE GRAPH

            Nodes: N1=code:orderapp | N2=iam_role:order_task_role | N3=s3:customer_data

            Edges (as emitted by the extractors — some over-approximate):
              N1→N2: deployed-as  INFERRED  a name convention, not a digest
              N2→N3: can-access   CERTAIN   see F4
            """;

        Assert.Equal(
            EdgeAssertionValidator.HopStatus.Confirmed,
            Assert.Single(EdgeAssertionValidator.Validate(arrowBrief, "N1 -> deployed-as -> N2")).Status);

        Assert.Equal(
            EdgeAssertionValidator.HopStatus.Reversed,
            Assert.Single(EdgeAssertionValidator.Validate(arrowBrief, "N3 -> can-access -> N2")).Status);

        Assert.Equal(
            EdgeAssertionValidator.HopStatus.Unrecognized,
            Assert.Single(EdgeAssertionValidator.Validate(arrowBrief, "N1 -> reaches -> N3")).Status);
    }

    [Fact]
    public void A_brief_with_no_edges_section_yields_no_findings()
    {
        // The walking skeleton's case — nothing to check against, so nothing is flagged.
        const string noEdges = "RESOURCE GRAPH\nNodes: N1=code:orderapp\n\nEdges: none were extracted for this scan.";

        Assert.Empty(EdgeAssertionValidator.Validate(noEdges, "N1 -> deployed-as -> N2"));
    }

    [Fact]
    public void The_verbose_technique_evidence_format_still_extracts_the_hop()
    {
        // Red's own instructed format: "node -> technique -> evidence", which repeats the
        // relation as a labelled segment rather than a bare word.
        var findings = EdgeAssertionValidator.Validate(
            ThreeNodeBrief,
            "N1:code:orderapp -> technique:deployed-as -> evidence:N2:iam_role:order_task_role");

        var finding = Assert.Single(findings);
        Assert.Equal(EdgeAssertionValidator.HopStatus.Confirmed, finding.Status);
    }

    [Fact]
    public void UnconfirmedDescriptions_omits_confirmed_hops()
    {
        var descriptions = EdgeAssertionValidator.UnconfirmedDescriptions(
            ThreeNodeBrief, "N1 -> deployed-as -> N2\nN3 -> can-access -> N2");

        var description = Assert.Single(descriptions);
        Assert.Contains("N3 -> N2", description);
    }

    /// <summary>
    /// The actual resource graph and Red round-2 transcript from the live run that exposed this
    /// bug, trimmed to the node range involved. Reproduced verbatim rather than simplified,
    /// because a simplified version is exactly the kind of copy that drifted from reality before
    /// (see the Sprint 3 audit's "the copy that drifts" pattern).
    /// </summary>
    [Fact]
    public void The_live_regression_is_caught_the_reversed_assumes_edge_and_nothing_else()
    {
        const string brief =
            """
            Nodes: N3=iam_role:order_task_role | N65=s3:build_artifacts_orphan | N66=s3:customer_data | N68=task:order_service | N69=task:order_task

            Edges (these are the only ones that exist — do not infer any other):
              N3 --can-access--> N65 (certain)
              N3 --can-access--> N66 (certain)
              N69 --assumes--> N3 (certain)
              N69 --can-access--> N68 (certain)
            """;

        const string redRound2 =
            """
            N3 -> can-access -> N65: This edge exists as per the given edges.
            N65 is s3:build_artifacts_orphan, which is a sensitive resource.
            N3 -> can-access -> N66: This edge also exists, and N66 is s3:customer_data, another sensitive resource.
            Since N3 has access to these sensitive resources, it's a good starting point.
            N3 -> assumes -> N69: This edge exists, and N69 is task:order_task.
            Now, N69 -> can-access -> N68: This edge exists, and N68 is task:order_service.

            The chain is:
            N3 -> can-access -> N65
            N3 -> assumes -> N69
            N69 -> can-access -> N68
            """;

        var findings = EdgeAssertionValidator.Validate(brief, redRound2);

        Assert.Equal(EdgeAssertionValidator.HopStatus.Confirmed, StatusOf(findings, "N3", "N65"));
        Assert.Equal(EdgeAssertionValidator.HopStatus.Confirmed, StatusOf(findings, "N3", "N66"));
        Assert.Equal(EdgeAssertionValidator.HopStatus.Confirmed, StatusOf(findings, "N69", "N68"));

        // The one hop that was actually wrong, and the one Blue rubber-stamped as CONFIRMED live.
        Assert.Equal(EdgeAssertionValidator.HopStatus.Reversed, StatusOf(findings, "N3", "N69"));

        var warnings = EdgeAssertionValidator.UnconfirmedDescriptions(brief, redRound2);
        var warning = Assert.Single(warnings);
        Assert.Contains("N3 -> N69", warning);
        Assert.Contains("N69 -> N3", warning);
    }

    /// <summary>
    /// A third live regression, same session: <c>N4 -&gt; used-by -&gt; N8</c> was correctly
    /// refuted by Blue in an earlier run over this exact node pair, and wrongly confirmed here —
    /// by chaining two real edges (<c>N8→N1</c>, <c>N1→N4</c>) into a fabricated third one via
    /// invalid transitive reasoning. Non-determinism in Blue's own judgement across runs is
    /// exactly why the mechanical check cannot depend on Blue agreeing with itself.
    /// </summary>
    [Fact]
    public void The_second_live_regression_is_caught_the_fabricated_transitive_edge()
    {
        const string brief =
            """
            Nodes: N1=code:orderapp | N4=image:tinyapp/order | N8=pkg:microsoft.data.sqlclient | N30=pkg:system.drawing.common

            Edges (these are the only ones that exist — do not infer any other):
              N30 --used-by--> N1 (certain)
              N1 --runs-as--> N4 (inferred)
              N8 --used-by--> N1 (certain)
            """;

        const string redTurn =
            "N30 --used-by--> N1 -> CWE-89 -> F50\r\n"
            + "N1 --runs-as--> N4 -> CWE-250 -> F65\r\n"
            + "N4 --used-by--> N8 -> CVE-2024-0056 -> F51";

        const string reporterTurn =
            "Chain: N30 --used-by--> N1 --runs-as--> N4 --used-by--> N8 \nSeverity: 4 \nVerdict: CHAIN_HOLDS";

        var warnings = EdgeAssertionValidator.UnconfirmedDescriptions(brief, $"{redTurn}\n{reporterTurn}");

        var warning = Assert.Single(warnings);
        Assert.Contains("N4 -> N8", warning);
        Assert.Contains("does not correspond to any edge", warning);
    }

    /// <summary>
    /// A fourth live regression, a different relation word and different nodes than the first —
    /// confirming the check generalizes rather than being fit to one case. Red asserted
    /// <c>code -&gt; used-by -&gt; pkg</c> on two separate hops; the real edges run
    /// <c>pkg --used-by--&gt; code</c>, both reversed. Blue confirmed both anyway.
    /// </summary>
    [Fact]
    public void The_third_live_regression_is_caught_two_reversed_used_by_edges()
    {
        const string brief =
            """
            Nodes: N23=pkg:sixlabors.imagesharp | N39=pkg:microsoft.data.sqlclient | N65=code:orderapp

            Edges (these are the only ones that exist — do not infer any other):
              N23 --used-by--> N65 (certain)
              N39 --used-by--> N65 (certain)
            """;

        const string redTurn =
            "N65:code:orderapp -> --used-by--> N23:pkg:sixlabors.imagesharp\r\n"
            + "N23:pkg:sixlabors.imagesharp -> (no direct edge to a finding, so we look for a related node)\r\n"
            + "N65:code:orderapp -> --used-by--> N39:pkg:microsoft.data.sqlclient\r\n"
            + "N39:pkg:microsoft.data.sqlclient -> (related to F51, a severity-4 finding)";

        var findings = EdgeAssertionValidator.Validate(brief, redTurn);

        Assert.Equal(EdgeAssertionValidator.HopStatus.Reversed, StatusOf(findings, "N65", "N23"));
        Assert.Equal(EdgeAssertionValidator.HopStatus.Reversed, StatusOf(findings, "N65", "N39"));
    }

    // ---- ValidateNodeLabels: the identity check, separate from the edge check --------------

    [Fact]
    public void A_correctly_labelled_node_reference_is_not_flagged()
    {
        var findings = EdgeAssertionValidator.ValidateNodeLabels(
            ThreeNodeBrief, "N1:code:orderapp -> deployed-as -> N2:iam_role:order_task_role");

        Assert.Empty(findings);
    }

    [Fact]
    public void A_node_labelled_as_something_it_is_not_is_flagged()
    {
        // N1 is really code:orderapp — this claims it is the resource N3 actually is.
        var findings = EdgeAssertionValidator.ValidateNodeLabels(
            ThreeNodeBrief, "N1:s3:customer_data -> deployed-as -> N2:iam_role:order_task_role");

        var finding = Assert.Single(findings);
        Assert.Equal("N1", finding.NodeRef);
        Assert.Equal("s3:customer_data", finding.ClaimedLabel);
        Assert.Equal("code:orderapp", finding.RealLabel);
        Assert.Contains("N1 is asserted as 's3:customer_data'", finding.Describe());
        Assert.Contains("real N1 is 'code:orderapp'", finding.Describe());
    }

    [Fact]
    public void A_real_edge_with_a_fabricated_label_is_still_flagged()
    {
        // The edge N1->N2 is real and correctly directed — only the identity of N1 is wrong.
        // The two checks are independent: a structurally sound hop can still misstate a node.
        const string text = "N1:s3:customer_data -> deployed-as -> N2:iam_role:order_task_role";

        var edgeFindings = EdgeAssertionValidator.Validate(ThreeNodeBrief, text);
        var labelFindings = EdgeAssertionValidator.ValidateNodeLabels(ThreeNodeBrief, text);

        Assert.Equal(EdgeAssertionValidator.HopStatus.Confirmed, Assert.Single(edgeFindings).Status);
        Assert.Single(labelFindings);
    }

    [Fact]
    public void Trailing_punctuation_on_a_claimed_label_does_not_cause_a_false_mismatch()
    {
        var findings = EdgeAssertionValidator.ValidateNodeLabels(ThreeNodeBrief, "N1:code:orderapp: this is the entry point.");

        Assert.Empty(findings);
    }

    [Fact]
    public void An_unknown_node_index_is_not_this_checks_job()
    {
        // N99 was never declared in the brief — nothing for this check to compare against.
        var findings = EdgeAssertionValidator.ValidateNodeLabels(ThreeNodeBrief, "N99:pkg:whatever -> used-by -> N1:code:orderapp");

        Assert.Empty(findings);
    }

    /// <summary>
    /// The question that came up live: was <c>N65:code:orderapp</c> a fabricated identity? In
    /// that run's actual submitted graph N65 genuinely was code:orderapp — this pins the
    /// non-hallucination case so the answer stays verifiable rather than re-argued from memory.
    /// </summary>
    [Fact]
    public void A_claim_matching_a_different_runs_real_graph_is_not_flagged_against_that_graph()
    {
        const string brief = "Nodes: N23=pkg:sixlabors.imagesharp | N39=pkg:microsoft.data.sqlclient | N65=code:orderapp";

        var findings = EdgeAssertionValidator.ValidateNodeLabels(
            brief, "N65:code:orderapp -> used-by -> N39:pkg:microsoft.data.sqlclient");

        Assert.Empty(findings);
    }

    private static EdgeAssertionValidator.HopStatus StatusOf(
        IReadOnlyList<EdgeAssertionValidator.HopFinding> findings, string from, string to) =>
        findings.Single(f => f.From == from && f.To == to).Status;
}

using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Tests.Debate;

/// <summary>
/// SEC-50 at the boundary: the decorator that wraps every real <see cref="IDebateEngine"/> call,
/// the same shape as <c>RedactingDebateEngine</c> and for the same reason — a guard nobody has
/// to remember to invoke.
/// </summary>
public class EdgeIntegrityDebateEngineTests
{
    private const string Brief =
        """
        Nodes: N1=code:orderapp | N2=iam_role:order_task_role | N3=s3:customer_data

        Edges (these are the only ones that exist — do not infer any other):
          N1 --deployed-as--> N2 (inferred)
          N2 --can-access--> N3 (certain)
        """;

    /// <summary>Returns a caller-supplied audit, so a test controls exactly what the inner engine produced.</summary>
    private sealed class StubEngine(DraftAudit audit) : IDebateEngine
    {
        public Task<DraftAudit> RunAsync(ScanBrief brief, CancellationToken ct = default) =>
            Task.FromResult(audit);
    }

    /// <summary>
    /// Puts <paramref name="content"/> in both the Red turn and the Reporter's closing turn —
    /// i.e. "what Red asserted is what got reported," the simple case most tests below want.
    /// Tests specifically about the reported/abandoned split build their own transcript instead.
    /// </summary>
    private static DraftAudit AuditWithRedContent(string content) => new()
    {
        Summary = "stub",
        Transcript =
        [
            new DebateTurn { Role = AgentRole.Red, Round = 1, Content = content },
            new DebateTurn { Role = AgentRole.Blue, Round = 1, Content = "validated", Converged = true },
            new DebateTurn { Role = AgentRole.Reporter, Round = 1, Content = content },
        ],
        Rounds = 1,
        TerminatedByTurnCap = false,
        Converged = true,
        WeakestJoin = Confidence.Certain,
    };

    private static EdgeIntegrityDebateEngine Wrap(DraftAudit audit) =>
        new(new StubEngine(audit), NullLogger<EdgeIntegrityDebateEngine>.Instance);

    [Fact]
    public async Task A_clean_assertion_produces_no_warnings()
    {
        var engine = Wrap(AuditWithRedContent("N1 -> deployed-as -> N2\nN2 -> can-access -> N3"));

        var result = await engine.RunAsync(new ScanBrief("job-1", Brief));

        Assert.Empty(result.EdgeIntegrityWarnings);
    }

    [Fact]
    public async Task A_reversed_hop_produces_a_warning_naming_both_directions()
    {
        var engine = Wrap(AuditWithRedContent("N3 -> can-access -> N2"));

        var result = await engine.RunAsync(new ScanBrief("job-1", Brief));

        var warning = Assert.Single(result.EdgeIntegrityWarnings);
        Assert.Contains("N3 -> N2", warning);
        Assert.Contains("N2 -> N3", warning);
    }

    [Fact]
    public async Task A_warning_never_changes_the_debates_own_outcome_or_confidence()
    {
        // The mechanical check is additive information, not a second verdict overwriting the
        // debate's. It does not know *why* a hop is wrong — only that it doesn't match — and
        // that is not grounds to override what the debate itself concluded.
        var input = AuditWithRedContent("N1 -> can-access -> N3"); // no edge in either direction

        var engine = Wrap(input);
        var result = await engine.RunAsync(new ScanBrief("job-1", Brief));

        Assert.NotEmpty(result.EdgeIntegrityWarnings);
        Assert.Equal(input.Converged, result.Converged);
        Assert.Equal(input.WeakestJoin, result.WeakestJoin);
        Assert.Equal(input.Outcome, result.Outcome);
    }

    [Fact]
    public async Task No_red_turn_at_all_is_not_an_error()
    {
        var noRed = new DraftAudit
        {
            Summary = "stub",
            Transcript = [],
            Rounds = 0,
            TerminatedByTurnCap = false,
            Converged = false,
        };

        var engine = Wrap(noRed);
        var result = await engine.RunAsync(new ScanBrief("job-1", Brief));

        Assert.Empty(result.EdgeIntegrityWarnings);
    }

    [Fact]
    public async Task Only_the_last_red_turn_is_checked_not_an_earlier_broken_assertion()
    {
        // Round 1 asserted something wrong and was broken — that is the debate working. Round 2
        // is what Blue's closing verdict actually responded to and what the Reporter adjudicated.
        var audit = new DraftAudit
        {
            Summary = "stub",
            Transcript =
            [
                new DebateTurn { Role = AgentRole.Red, Round = 1, Content = "N3 -> can-access -> N2" }, // reversed
                new DebateTurn { Role = AgentRole.Blue, Round = 1, Content = "broken", Converged = false },
                new DebateTurn { Role = AgentRole.Red, Round = 2, Content = "N1 -> deployed-as -> N2" }, // correct
                new DebateTurn { Role = AgentRole.Blue, Round = 2, Content = "holds", Converged = true },
                new DebateTurn { Role = AgentRole.Reporter, Round = 2, Content = "N1 -> deployed-as -> N2" },
            ],
            Rounds = 2,
            TerminatedByTurnCap = false,
            Converged = true,
        };

        var engine = Wrap(audit);
        var result = await engine.RunAsync(new ScanBrief("job-1", Brief));

        Assert.Empty(result.EdgeIntegrityWarnings);
        Assert.Empty(result.AbandonedReasoningWarnings);
    }

    /// <summary>
    /// The second live regression: Red left a hop unfinished (<c>N1 -&gt; deployed-as -&gt;
    /// (no direct edge, but)</c> — no target node named), Blue "completed" it into a specific,
    /// nonexistent pairing, and the Reporter repeated Blue's fabrication as the chain's own
    /// citation. Red's own text has nothing to catch; only checking the Reporter's turn does.
    /// </summary>
    [Fact]
    public async Task A_pairing_blue_invents_and_the_reporter_repeats_is_caught_via_the_reporter_turn()
    {
        // N3 has no edges to anything — the fabrication is N2 -> N3, which cannot be confused
        // with a real edge in either direction.
        const string brief =
            """
            Nodes: N1=code:orderapp | N2=image:tinyapp/order | N3=task:order_task

            Edges (these are the only ones that exist — do not infer any other):
              N1 --runs-as--> N2 (inferred)
            """;

        var audit = new DraftAudit
        {
            Summary = "stub",
            Transcript =
            [
                new DebateTurn
                {
                    Role = AgentRole.Red, Round = 2,
                    // Red never names a target for the second hop — nothing for a Red-only check to find.
                    Content = "N1 -> runs-as -> N2\nN2 -> deployed-as -> (no direct edge, but)",
                },
                new DebateTurn
                {
                    Role = AgentRole.Blue, Round = 2, Converged = true,
                    // Blue invents the pairing N2 -> N3 while "completing" Red's hedge.
                    Content = "N1 -> runs-as -> N2: CONFIRMED\nN2 -> deployed-as -> N3: UNRESOLVED\nVERDICT: CHAIN_HOLDS",
                },
                new DebateTurn
                {
                    Role = AgentRole.Reporter, Round = 2,
                    Content = "Potential chain, unverified join: N1 -> runs-as -> N2 -> deployed-as -> N3 [1]\n"
                        + "Reference: [1] Edge N2 -> deployed-as -> N3 is unresolved.",
                },
            ],
            Rounds = 2,
            TerminatedByTurnCap = false,
            Converged = true,
            WeakestJoin = Confidence.Unresolved,
        };

        var engine = Wrap(audit);
        var result = await engine.RunAsync(new ScanBrief("job-1", brief));

        var warning = Assert.Single(result.EdgeIntegrityWarnings);
        Assert.Contains("N2 -> N3", warning);
    }

    /// <summary>
    /// Blue is checked, but a fabrication only Blue states and the Reporter's own text never
    /// repeats lands as informational, not as a reported-chain warning — see the third live
    /// regression below for why: capping a genuinely clean reported chain at <c>Asserted</c>
    /// because of reasoning the Reporter itself discarded is the wrong trade, not a stricter one.
    /// </summary>
    [Fact]
    public async Task A_bad_pairing_only_blue_states_is_informational_not_reported()
    {
        var audit = new DraftAudit
        {
            Summary = "stub",
            Transcript =
            [
                new DebateTurn { Role = AgentRole.Red, Round = 1, Content = "N1 -> deployed-as -> N2" },
                new DebateTurn
                {
                    Role = AgentRole.Blue, Round = 1, Converged = true,
                    // Blue introduces a pair Red never asserted and the Reporter never repeats.
                    Content = "N1 -> deployed-as -> N2: CONFIRMED\nN2 -> deployed-as -> N1: also true\nVERDICT: CHAIN_HOLDS",
                },
                new DebateTurn { Role = AgentRole.Reporter, Round = 1, Content = "Chain confirmed. Severity 4." },
            ],
            Rounds = 1,
            TerminatedByTurnCap = false,
            Converged = true,
        };

        var engine = Wrap(audit);
        var result = await engine.RunAsync(new ScanBrief("job-1", Brief));

        // Not in the reported bucket — the Reporter's own text never named N2/N1 at all.
        Assert.Empty(result.EdgeIntegrityWarnings);

        // But visible to a human reading the full transcript. N2 -> N1 is the reverse of the
        // one real edge N1 -> N2 — Blue asserted it unprompted.
        var warning = Assert.Single(result.AbandonedReasoningWarnings);
        Assert.Contains("N2 -> N1", warning);
    }

    /// <summary>
    /// The third live regression: Red asserted two candidate paths in one turn — one fabricated
    /// (<c>N4 -&gt; used-by -&gt; N8</c>, no such edge exists), one entirely real. Blue never
    /// addressed the fabricated one at all, yet still returned CHAIN_HOLDS; the Reporter reported
    /// only the real path. The reported chain is genuinely clean and must not be downgraded for
    /// reasoning nobody acted on.
    /// </summary>
    [Fact]
    public async Task An_abandoned_fabricated_path_does_not_cap_a_genuinely_clean_reported_chain()
    {
        const string brief =
            """
            Nodes: N1=code:orderapp | N3=iam_role:order_task_role | N4=image:tinyapp/order | N8=pkg:microsoft.data.sqlclient | N65=s3:build_artifacts_orphan | N69=task:order_task

            Edges (these are the only ones that exist — do not infer any other):
              N1 --runs-as--> N4 (inferred)
              N1 --deployed-as--> N69 (inferred)
              N3 --can-access--> N65 (certain)
              N8 --used-by--> N1 (certain)
              N69 --assumes--> N3 (certain)
            """;

        var audit = new DraftAudit
        {
            Summary = "stub",
            Transcript =
            [
                new DebateTurn
                {
                    Role = AgentRole.Red, Round = 1,
                    Content =
                        "N1:code:orderapp -> runs-as -> N4:image:tinyapp/order -> used-by -> N8:pkg:microsoft.data.sqlclient\n"
                        + "N8:pkg:microsoft.data.sqlclient -> used-by -> N1:code:orderapp -> deployed-as -> N69:task:order_task\n"
                        + "N69:task:order_task -> assumes -> N3:iam_role:order_task_role -> can-access -> N65:s3:build_artifacts_orphan",
                },
                new DebateTurn
                {
                    Role = AgentRole.Blue, Round = 1, Converged = true,
                    // Blue never mentions N4 at all — the fabricated path goes unaddressed, not refuted.
                    Content = "N8:pkg:microsoft.data.sqlclient -> used-by -> N1:code:orderapp: CONFIRMED\n"
                        + "N1:code:orderapp -> deployed-as -> N69:task:order_task: CONFIRMED\n"
                        + "N69:task:order_task -> assumes -> N3:iam_role:order_task_role: CONFIRMED\n"
                        + "N3:iam_role:order_task_role -> can-access -> N65:s3:build_artifacts_orphan: CONFIRMED\n"
                        + "VERDICT: CHAIN_HOLDS",
                },
                new DebateTurn
                {
                    Role = AgentRole.Reporter, Round = 1,
                    Content = "Chain confirmed: N8 -> N1 -> N69 -> N3 -> N65",
                },
            ],
            Rounds = 1,
            TerminatedByTurnCap = false,
            Converged = true,
        };

        var engine = Wrap(audit);
        var result = await engine.RunAsync(new ScanBrief("job-1", brief));

        // The reported chain is entirely real — nothing should cap ChainOutcomeWriter here.
        Assert.Empty(result.EdgeIntegrityWarnings);

        // But the abandoned N4 -> N8 fabrication is still visible to a human reading the transcript.
        var warning = Assert.Single(result.AbandonedReasoningWarnings);
        Assert.Contains("N4 -> N8", warning);
    }

    /// <summary>SEC-50's second check: a real, correctly-directed edge whose endpoint is mislabelled.</summary>
    [Fact]
    public async Task A_mislabelled_node_is_flagged_even_when_the_edge_itself_is_real()
    {
        var engine = Wrap(AuditWithRedContent("N1:s3:customer_data -> deployed-as -> N2:iam_role:order_task_role"));

        var result = await engine.RunAsync(new ScanBrief("job-1", Brief));

        var warning = Assert.Single(result.EdgeIntegrityWarnings);
        Assert.Contains("N1 is asserted as 's3:customer_data'", warning);
        Assert.Contains("real N1 is 'code:orderapp'", warning);
    }
}

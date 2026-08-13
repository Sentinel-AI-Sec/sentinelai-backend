using SentinelAI.Application.Features.Scan.Reporting;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Handoff;

/// <summary>
/// Boundary 6 — Reporter → PR. The report that leaves the backend must always be framed as a
/// draft audit, and an unresolved-join result must never be dressed up as a confirmed finding.
/// </summary>
/// <remarks>
/// <para>
/// There is no PR-comment component yet, so the object that crosses this boundary is the
/// <see cref="Report"/> itself. Two invariants matter here. First, AID-01 §7:
/// <see cref="Report.Framing"/> is the constant <c>draft_audit</c> — the output is prioritized
/// material for human review, never a verdict — and it is a constant precisely so no confidence
/// level can promote it to "confirmed."
/// </para>
/// <para>
/// Second, the unresolved distinction: a chain whose weakest join is
/// <see cref="Confidence.Unresolved"/> is carried as exactly that on the <see cref="DraftAudit"/>,
/// and the report framing does not upgrade with it. (The report model carries the distinction via
/// the audit's weakest-join and the Reporter's text, not a structured field — noted so the seam is
/// honest about where the signal lives.)
/// </para>
/// </remarks>
public class ReporterToPrHandoffTests
{
    private static readonly Guid Tenant = HandoffFixture.Tenant;
    private static readonly Guid Job = HandoffFixture.Job;

    [Fact]
    public async Task The_report_is_always_framed_as_a_draft_audit_never_a_verdict()
    {
        var result = await HandoffFixture.BuildPipeline()
            .RunAsync([HandoffFixture.SeededFinding()], Tenant, Job);

        Assert.Equal("draft_audit", result.Report.Framing);
        Assert.Equal(ReportBuilder.DraftAudit, result.Report.Framing);

        // The framing is not a bare label — the disclaimer travels in the text a renderer shows.
        Assert.Contains("not a verified verdict", result.Report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_unresolved_join_stays_a_draft_and_is_not_promoted_to_confirmed()
    {
        // A result whose weakest join could not be confirmed.
        var unresolved = Audit("Potential chain — unverified join at the code->infra seam.", Confidence.Unresolved);
        var confirmed = Audit("Chain confirmed against the real configuration.", Confidence.Certain);

        var fromUnresolved = await HandoffFixture.BuildPipeline(new StubDebate(unresolved))
            .RunAsync([HandoffFixture.SeededFinding()], Tenant, Job);
        var fromConfirmed = await HandoffFixture.BuildPipeline(new StubDebate(confirmed))
            .RunAsync([HandoffFixture.SeededFinding()], Tenant, Job);

        // Confidence never turns into a stronger framing: both are draft audits, so an unresolved
        // chain can never reach a reader labelled "confirmed."
        Assert.Equal("draft_audit", fromUnresolved.Report.Framing);
        Assert.Equal("draft_audit", fromConfirmed.Report.Framing);

        // The unresolved signal is carried distinctly, not flattened into the confirmed case.
        Assert.Equal(Confidence.Unresolved, fromUnresolved.Audit.WeakestJoin);
        Assert.NotEqual(fromUnresolved.Audit.WeakestJoin, fromConfirmed.Audit.WeakestJoin);

        // And the reporter's unresolved wording survives into the report a human reads.
        Assert.Contains("unverified join", fromUnresolved.Report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    private static DraftAudit Audit(string summary, Confidence weakestJoin) => new()
    {
        Summary = summary,
        Transcript =
        [
            new DebateTurn { Role = AgentRole.Blue, Round = 1, Content = "validated", Confidence = weakestJoin },
        ],
        Rounds = 1,
        TerminatedByTurnCap = false,
        Converged = true,
        WeakestJoin = weakestJoin,
    };
}

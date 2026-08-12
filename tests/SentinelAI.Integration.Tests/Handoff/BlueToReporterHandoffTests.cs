using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Handoff;

/// <summary>
/// Boundary 5 — Blue → Reporter. Every Blue verdict that reaches the Reporter must be a definite,
/// readable judgement — never an ambiguous or unparsed one silently treated as agreement.
/// </summary>
/// <remarks>
/// <para>
/// The ticket frames this as "every hop has <c>blue_validated</c> set to a definite true/false,
/// never null." The running pipeline models Blue's judgement not as a nullable bool on a
/// <c>ChainHop</c> (that persistence field is a non-nullable <c>bool</c>, so "never null" there is
/// vacuous), but as <see cref="DebateTurn.VerdictReadable"/> plus a <see cref="Confidence"/> on the
/// turn. Its honest analogue: a Blue turn crosses the seam with a verdict that could actually be
/// read, and a confidence the Reporter can act on.
/// </para>
/// <para>
/// This is a real regression the field exists to catch: a model that truncated mid-sentence once
/// had "no verdict" collapse into "the chain holds," and a broken chain was published as clean.
/// <see cref="DebateTurn.VerdictReadable"/> keeps "unreadable" distinct from "confirmed", and the
/// Reporter must receive that distinction, not a silent default.
/// </para>
/// </remarks>
public class BlueToReporterHandoffTests
{
    [Fact]
    public async Task Every_blue_verdict_reaching_the_reporter_is_definite_and_readable()
    {
        var result = await HandoffFixture.BuildPipeline()
            .RunAsync([HandoffFixture.SeededFinding()], HandoffFixture.Tenant, HandoffFixture.Job);

        var blue = result.Audit.Transcript.Where(t => t.Role == AgentRole.Blue).ToList();
        Assert.NotEmpty(blue);

        Assert.All(blue, t =>
        {
            // A definite, readable verdict — not "no verdict" quietly reported as agreement.
            Assert.True(t.VerdictReadable, "Blue's verdict must be readable, never silently defaulted");
            // A confidence the Reporter can act on, never an unset enum.
            Assert.True(Enum.IsDefined(t.Confidence));
        });
    }

    [Fact]
    public async Task The_reporter_receives_blues_verdict_and_adjudicates_a_definite_outcome()
    {
        var result = await HandoffFixture.BuildPipeline()
            .RunAsync([HandoffFixture.SeededFinding()], HandoffFixture.Tenant, HandoffFixture.Job);

        // The Reporter ran on Blue's output: a non-empty adjudication and a defined outcome, plus a
        // weakest-join confidence carried forward for the report to surface.
        Assert.False(string.IsNullOrWhiteSpace(result.Audit.Summary));
        Assert.True(Enum.IsDefined(result.Audit.Outcome), "the debate must report a definite outcome");
        Assert.True(Enum.IsDefined(result.Audit.WeakestJoin));
    }
}

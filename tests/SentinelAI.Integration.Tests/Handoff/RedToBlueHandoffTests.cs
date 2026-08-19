using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Handoff;

/// <summary>
/// Boundary 4 — Red → Blue. Red's asserted chain must reach Blue with content to validate, and a
/// confidence Blue can downgrade.
/// </summary>
/// <remarks>
/// <para>
/// The ticket frames this as "every hop carries a non-empty technique_id and evidence." In the
/// running pipeline Red does not emit typed <c>ChainHop</c> rows — it emits a <see cref="DebateTurn"/>
/// whose <see cref="DebateTurn.Content"/> states each hop as <c>node -&gt; technique -&gt; evidence</c>
/// (per Red's own instructions), and Blue validates that text. So this drives the <em>real</em>
/// debate engine (over the offline scripted provider) and asserts on the actual turns that cross
/// the seam: Red asserted something non-empty, and Blue received it and responded.
/// </para>
/// <para>
/// Confidence is the piece the ticket calls out explicitly: Red asserts at
/// <see cref="Confidence.Certain"/> and does not decide — Blue is what downgrades a hop on
/// inspection. That split is the false-positive reducer, and it is asserted here.
/// </para>
/// </remarks>
public class RedToBlueHandoffTests
{
    [Fact]
    public async Task Red_asserts_a_non_empty_chain_and_blue_receives_it()
    {
        var result = await HandoffFixture.BuildPipeline()
            .RunAsync([HandoffFixture.SeededFinding()], HandoffFixture.Tenant, HandoffFixture.Job);

        var red = result.Audit.Transcript.Where(t => t.Role == AgentRole.Red).ToList();
        var blue = result.Audit.Transcript.Where(t => t.Role == AgentRole.Blue).ToList();

        // Red asserted something for Blue to judge — an empty assertion is nothing to validate.
        Assert.NotEmpty(red);
        Assert.All(red, t => Assert.False(string.IsNullOrWhiteSpace(t.Content)));

        // Blue ran, which only happens if Red's turn was handed across the seam.
        Assert.NotEmpty(blue);
    }

    [Fact]
    public async Task Red_asserts_at_full_confidence_and_leaves_the_downgrade_to_blue()
    {
        var result = await HandoffFixture.BuildPipeline()
            .RunAsync([HandoffFixture.SeededFinding()], HandoffFixture.Tenant, HandoffFixture.Job);

        // Red does not decide confidence; it asserts at Certain and Blue downgrades on inspection.
        // Every Red turn must still carry a defined confidence value across the seam, never an
        // unset enum.
        Assert.All(
            result.Audit.Transcript.Where(t => t.Role == AgentRole.Red),
            t =>
            {
                Assert.True(Enum.IsDefined(t.Confidence));
                Assert.Equal(Confidence.Certain, t.Confidence);
            });
    }
}

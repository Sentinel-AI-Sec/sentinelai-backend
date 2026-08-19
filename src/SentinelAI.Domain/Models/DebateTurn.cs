using SentinelAI.Domain.Enums;

namespace SentinelAI.Domain.Models;

/// <summary>
/// One agent's contribution to the debate. This is the message that flows along the
/// workflow edges, and the unit that accumulates in shared session state.
/// </summary>
public sealed record DebateTurn
{
    /// <summary>Which agent produced this turn.</summary>
    public required AgentRole Role { get; init; }

    /// <summary>1-based debate round. Red and Blue share a round number; Reporter closes it.</summary>
    public required int Round { get; init; }

    /// <summary>The agent's output text.</summary>
    public required string Content { get; init; }

    /// <summary>
    /// Weakest join confidence this turn depends on. Reporter surfaces anything
    /// <see cref="Enums.Confidence.Unresolved"/> as "potential chain, unverified join".
    /// </summary>
    /// <remarks>
    /// Deliberately the same <see cref="Enums.Confidence"/> a <see cref="GraphEdge"/> carries.
    /// The debate's verdict has to be writable back onto the graph, and two enums for one
    /// concept is how that quietly stops being true.
    /// </remarks>
    public Confidence Confidence { get; init; } = Enums.Confidence.Certain;

    /// <summary>
    /// Set by Blue when it cannot break any link — the convergence signal the
    /// orchestrator reads to end the debate before the turn-cap.
    /// </summary>
    public bool Converged { get; init; }

    /// <summary>
    /// False when Blue's verdict token could not be parsed from the response.
    /// </summary>
    /// <remarks>
    /// This exists because "no verdict" and "the chain holds" are completely different
    /// claims that used to collapse into the same <see cref="Converged"/> flag. A live run
    /// where the model exhausted its token budget mid-sentence was reported as a converged
    /// debate. Routing still exits to the Reporter — a failed parse must not burn the
    /// turn-cap — but the outcome is now labelled for what it is.
    /// </remarks>
    public bool VerdictReadable { get; init; } = true;

    /// <summary>
    /// Which model tier served this turn (SEC-31). Stamped by the executor from the routing
    /// policy it was built with, so the transcript itself is the evidence that reasoning turns
    /// went to the high tier and routine ones did not.
    /// </summary>
    /// <remarks>
    /// Recorded per turn rather than looked up per role after the fact. A role's tier is
    /// configurable, so reading it back from configuration at report time would describe
    /// whatever the settings say <em>now</em> rather than what actually ran.
    /// </remarks>
    public ModelTier Tier { get; init; } = ModelTier.High;

    /// <summary>
    /// Tokens the provider billed for this turn, or <see cref="TokenUsage.None"/> when it
    /// reported none. Aggregated by tier into <see cref="DraftAudit.Cost"/>.
    /// </summary>
    public TokenUsage Usage { get; init; } = TokenUsage.None;

    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

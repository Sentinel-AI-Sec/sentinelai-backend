using SentinelAI.Domain.Enums;

namespace SentinelAI.Domain.Models;

/// <summary>
/// The Reporter's adjudicated output. Framed as a draft for human review, never a
/// verified verdict (AID-01 section 7).
/// </summary>
public sealed record DraftAudit
{
    public required string Summary { get; init; }
    public required IReadOnlyList<DebateTurn> Transcript { get; init; }
    public required int Rounds { get; init; }
    public required bool TerminatedByTurnCap { get; init; }
    public required bool Converged { get; init; }

    /// <summary>False when the closing verdict could not be parsed. See <see cref="Outcome"/>.</summary>
    public bool VerdictReadable { get; init; } = true;

    /// <summary>
    /// The honest one-word answer to "how did this end?". Checked most-doubtful first, so
    /// an unparseable verdict can never be reported as a convergence.
    /// </summary>
    public DebateOutcome Outcome =>
        !VerdictReadable ? DebateOutcome.VerdictUnreadable
        : TerminatedByTurnCap ? DebateOutcome.TurnCapped
        : Converged ? DebateOutcome.Converged
        : DebateOutcome.ChainBroken;

    /// <summary>Weakest confidence across the whole transcript (AID-01 section 3.3).</summary>
    public Confidence WeakestJoin { get; init; } = Confidence.Certain;

    /// <summary>Non-negotiable framing per AID-01 section 7.</summary>
    public string Disclaimer =>
        "Prioritized draft audit for human review — not a verified verdict.";
}

namespace SentinelAI.Domain.Models;

/// <summary>
/// How the debate actually ended. Replaces the ambiguous converged/not-converged pair.
/// </summary>
public enum DebateOutcome
{
    /// <summary>Blue confirmed it could not break the chain.</summary>
    Converged,

    /// <summary>Blue broke a link and the debate ran out of rounds.</summary>
    ChainBroken,

    /// <summary>The turn-cap stopped the debate before it resolved.</summary>
    TurnCapped,

    /// <summary>Blue produced no parseable verdict. Not evidence of anything.</summary>
    VerdictUnreadable
}

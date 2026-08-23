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
    VerdictUnreadable,

    /// <summary>
    /// No debate was run at all — the tenant's plan does not include adjudication.
    /// </summary>
    /// <remarks>
    /// The absence of a verdict, and emphatically not a verdict. Every other member here reports
    /// something that happened during a debate; this one says nobody looked. Rendering it as a
    /// failure would state a result no agent produced, which is the same mistake the five-value
    /// <c>HopVerdict</c> exists to prevent one level down.
    /// </remarks>
    NotAdjudicated
}

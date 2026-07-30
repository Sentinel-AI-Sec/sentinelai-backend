namespace SentinelAI.Domain.Models;

/// <summary>
/// AID-01 section 3.3. A chain inherits the weakest edge's confidence, so a single
/// unresolved hop marks the whole chain for human review.
/// </summary>
/// <remarks>
/// Ordered weakest-first on purpose: <c>Min()</c> over a transcript is then literally the
/// weakest-link rule, so the precedence cannot drift away from the design document.
/// </remarks>
public enum JoinConfidence
{
    Unresolved = 0,
    Inferred = 1,
    Certain = 2
}

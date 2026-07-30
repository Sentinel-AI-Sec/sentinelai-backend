namespace SentinelAI.Application.Debate;

/// <summary>
/// Model-tier routing from AID-01 section 2.1. The orchestrator routes reasoning-heavy
/// debate turns to the high tier and routine turns to the cheap tier.
/// </summary>
/// <remarks>
/// This is policy — WHICH class of model a role deserves. Which vendor and model id that
/// resolves to is a HOW, and lives with the provider options in Infrastructure.
/// </remarks>
public enum ModelTier
{
    /// <summary>Debate turns: chaining, link validation, adjudication.</summary>
    High,

    /// <summary>High-volume routine turns, formatting, summarization.</summary>
    Cheap
}

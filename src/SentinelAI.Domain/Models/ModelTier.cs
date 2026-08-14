namespace SentinelAI.Domain.Models;

/// <summary>
/// Model-tier routing from AID-01 section 2.1. Reasoning-heavy debate turns go to the high
/// tier and routine turns to the cheap tier.
/// </summary>
/// <remarks>
/// <para>
/// This is policy — WHICH class of model a turn deserves. Which vendor and model id that
/// resolves to is a HOW, and lives with the provider options in Infrastructure.
/// </para>
/// <para>
/// It lives in the Domain rather than in <c>SentinelAI.Application.Debate</c>, where SEC-02
/// put it, because SEC-31 made the tier a fact the debate <em>records</em> and not only a
/// setting it reads: every <see cref="DebateTurn"/> is stamped with the tier that produced
/// it, and <see cref="AuditCost"/> breaks spend down by tier. Both are Domain types, and the
/// Domain cannot reference the Application layer.
/// </para>
/// </remarks>
public enum ModelTier
{
    /// <summary>Reasoning-heavy turns: chaining, link validation, adjudication.</summary>
    High,

    /// <summary>High-volume routine turns: briefing, formatting, summarization.</summary>
    Cheap
}

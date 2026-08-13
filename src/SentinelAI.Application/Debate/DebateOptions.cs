using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Debate;

/// <summary>
/// Policy knobs the Orchestrator enforces over the debate.
/// </summary>
public sealed class DebateOptions
{
    public const string SectionName = "SentinelAI:Debate";

    /// <summary>
    /// The turn-cap. Red+Blue exchange at most this many rounds before the Orchestrator
    /// routes to the Reporter regardless of whether the debate converged. Guarantees
    /// termination, which is a hard SEC-02 acceptance criterion.
    /// </summary>
    public int MaxRounds { get; set; } = 3;

    /// <summary>
    /// The SEC-31 routing policy: which tier each role's turn is worth (AID-01 2.1).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The split follows the three reasoning-heavy turns AID-01 names — chaining (Red),
    /// link validation (Blue), and adjudication (Reporter) — against the one routine turn.
    /// The Orchestrator neither asserts nor rebuts: it reads the graph and writes a short
    /// briefing, which is the "high-volume routine" work the cheap tier exists for.
    /// </para>
    /// <para>
    /// Overridable per role from <c>SentinelAI:Debate:Tiers</c>, because a demo may want
    /// everything cheap and a benchmark may want everything high. What is not overridable is
    /// that the choice is recorded: whatever this map says, the tier that actually served a
    /// turn is stamped on that turn and shows up in the audit's cost breakdown.
    /// </para>
    /// </remarks>
    public IDictionary<AgentRole, ModelTier> Tiers { get; } =
        new Dictionary<AgentRole, ModelTier>(DefaultTiers);

    /// <summary>
    /// The shipped routing policy, separate from the mutable instance so a test can assert
    /// the default without reading it back off an options object something may have edited.
    /// </summary>
    public static IReadOnlyDictionary<AgentRole, ModelTier> DefaultTiers { get; } =
        new Dictionary<AgentRole, ModelTier>
        {
            // Routine: briefs Red from the graph, asserts nothing.
            [AgentRole.Orchestrator] = ModelTier.Cheap,

            // Reasoning-heavy: chaining, link validation, adjudication.
            [AgentRole.Red] = ModelTier.High,
            [AgentRole.Blue] = ModelTier.High,
            [AgentRole.Reporter] = ModelTier.High
        };

    /// <summary>
    /// Ceiling on tokens per agent turn. Latency scales with tokens generated, and a
    /// reasoning model left uncapped will spend hundreds of tokens narrating its thinking
    /// before answering — measured at 436 tokens for a 68-token prompt. A debate turn is a
    /// few sentences, so the cap costs nothing and roughly halves wall-clock time.
    /// </summary>
    /// <remarks>
    /// 400 was too tight against a reasoning model: the whole budget went on its thinking
    /// preamble and every turn was truncated mid-word before reaching an answer — Blue's
    /// verdict token never appeared at all. The cap has to clear the preamble, so terse
    /// instructions do the real shortening and this only stops a runaway.
    /// </remarks>
    public int MaxOutputTokens { get; set; } = 4000;

    /// <summary>
    /// Low by default. This is adversarial security reasoning over a fixed graph, not
    /// creative writing — and lower temperature also shortens responses.
    /// </summary>
    public float Temperature { get; set; } = 0.2f;

    // There is deliberately no RequestTimeout here. The per-call ceiling is applied to the
    // HTTP pipeline when the client is built, which happens before these options are in
    // scope, so it lives on ModelProviderOptions (SentinelAI:Models:RequestTimeout). A copy
    // on this type was bound from SentinelAI:Debate and read by nothing — setting it looked
    // like it worked and changed no behaviour.

    /// <summary>
    /// The tier that will serve this role's turns.
    /// </summary>
    /// <remarks>
    /// Falls back to the shipped default rather than to <see cref="ModelTier.High"/>. The old
    /// blanket fallback made every unmapped role expensive, so a role dropped from the map —
    /// which configuration can do, since binding replaces entries — silently moved the
    /// Orchestrator's routine briefing onto the reasoning model and nothing said so.
    /// </remarks>
    public ModelTier TierFor(AgentRole role) =>
        Tiers.TryGetValue(role, out var tier) ? tier
        : DefaultTiers.TryGetValue(role, out var shipped) ? shipped
        : ModelTier.High;

    /// <summary>
    /// Throws if the configured policy could never terminate correctly. Public because
    /// Infrastructure enforces it when building the workflow, across the layer boundary.
    /// </summary>
    public void Validate()
    {
        if (MaxRounds < 1)
            throw new ArgumentOutOfRangeException(
                nameof(MaxRounds), MaxRounds, "The turn-cap must allow at least one round.");
    }
}

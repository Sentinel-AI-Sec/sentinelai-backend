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
    /// Model tier per role (AID-01 2.1). All three are reasoning-heavy turns by default;
    /// the cheap tier exists for routine formatting work added later.
    /// </summary>
    public IDictionary<AgentRole, ModelTier> Tiers { get; } = new Dictionary<AgentRole, ModelTier>
    {
        [AgentRole.Orchestrator] = ModelTier.Cheap,
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

    /// <summary>
    /// Per-call ceiling. Without it a stalled provider hangs the whole debate with no
    /// output and no error, which is indistinguishable from the run being slow.
    /// </summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(120);

    public ModelTier TierFor(AgentRole role) =>
        Tiers.TryGetValue(role, out var tier) ? tier : ModelTier.High;

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

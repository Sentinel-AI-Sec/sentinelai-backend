using System.Text.Json.Serialization;

namespace SentinelAI.Domain.Models;

/// <summary>
/// The shared session state every agent reads and appends to.
/// </summary>
/// <remarks>
/// The keys this is stored under belong to the orchestration runtime, not to the domain,
/// so they live in <c>SentinelAI.Infrastructure.Agents.DebateStateKeys</c>. This record
/// stays a plain, serializable projection of the debate so far — which is also what makes
/// it safe to persist in a checkpoint and restore into a resumed run.
/// </remarks>
public sealed record DebateState
{
    /// <summary>Every turn taken so far, in order. Append-only.</summary>
    public IReadOnlyList<DebateTurn> Transcript { get; init; } = [];

    /// <summary>
    /// The resource graph seeded by the Orchestrator. Persisted in shared state so every
    /// agent — and any resumed run — has the full graph context without re-reading the brief.
    /// </summary>
    public string ResourceGraph { get; init; } = string.Empty;

    /// <summary>
    /// Highest round reached so far. Maintained by <see cref="Append"/> from the turns
    /// themselves rather than by any one executor.
    /// </summary>
    /// <remarks>
    /// It used to be documented as "incremented by Red" and then never incremented by
    /// anything — the Orchestrator set it to 0 and it stayed there for the whole debate.
    /// Because this record is what gets serialized into every checkpoint, a resumed run and
    /// any future consumer of shared state read round 0 no matter how far the debate got.
    /// Deriving it from the transcript means it cannot drift out of step again.
    /// </remarks>
    public int Round { get; init; }

    /// <summary>True once Blue reports it cannot break the chain.</summary>
    public bool Converged { get; init; }

    /// <summary>True once the orchestrator stopped the debate for hitting the turn-cap.</summary>
    public bool TurnCapReached { get; init; }

    /// <summary>
    /// The Orchestrator's round-0 briefing turn, kept out of <see cref="Transcript"/>.
    /// </summary>
    /// <remarks>
    /// The seed is not a debate turn — nobody asserts or rebuts anything in it — so counting
    /// it in the transcript would inflate <see cref="TurnCount"/> and every round number
    /// derived from it. But when the Orchestrator is model-backed it is a real, billed model
    /// call, and SEC-31's cost figure is wrong if it is dropped. Holding it here keeps the
    /// transcript honest and the accounting complete, and being part of this record means it
    /// survives a checkpoint like everything else.
    /// </remarks>
    public DebateTurn? Seed { get; init; }

    /// <summary>Every model-backed turn this debate ran, the seed included, in order.</summary>
    [JsonIgnore]
    public IEnumerable<DebateTurn> AllTurns =>
        Seed is null ? Transcript : Transcript.Prepend(Seed);

    [JsonIgnore]
    public int TurnCount => Transcript.Count;

    public DebateState Append(DebateTurn turn)
    {
        ArgumentNullException.ThrowIfNull(turn);

        return this with
        {
            Transcript = [.. Transcript, turn],
            Round = Math.Max(Round, turn.Round),
        };
    }
}

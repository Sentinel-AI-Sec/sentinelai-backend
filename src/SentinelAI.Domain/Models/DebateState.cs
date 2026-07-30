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

    /// <summary>Current round. Incremented by Red at the head of each round.</summary>
    public int Round { get; init; }

    /// <summary>True once Blue reports it cannot break the chain.</summary>
    public bool Converged { get; init; }

    /// <summary>True once the orchestrator stopped the debate for hitting the turn-cap.</summary>
    public bool TurnCapReached { get; init; }

    [JsonIgnore]
    public int TurnCount => Transcript.Count;

    public DebateState Append(DebateTurn turn) =>
        this with { Transcript = [.. Transcript, turn] };
}

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

    /// <summary>
    /// What the mechanical check (SEC-50) found <em>in the chain the Reporter actually reported</em>
    /// — a hop naming two nodes with no real edge between them (in either direction), or a node
    /// annotated with an identity the resource graph never declared. Checked against the graph
    /// itself, never against what an LLM's own reading of the same text concluded. Non-empty here
    /// means the reported chain itself is suspect, which is why <c>ChainOutcomeWriter</c> reads
    /// this field specifically. Empty on a clean debate.
    /// </summary>
    public IReadOnlyList<string> EdgeIntegrityWarnings { get; init; } = [];

    /// <summary>
    /// The same two checks (SEC-50), but for hops that appeared only in Red's or Blue's raw
    /// reasoning and were not part of what the Reporter actually reported — a candidate path
    /// considered and dropped, not the chain a reader is being asked to trust.
    /// </summary>
    /// <remarks>
    /// A live run had Red assert two candidate paths in one turn; the Reporter kept the clean one
    /// and silently discarded the other, which contained a fabricated edge. Folding that into
    /// <see cref="EdgeIntegrityWarnings"/> would have capped a genuinely valid, fully-grounded
    /// chain at <c>Asserted</c> for reasoning nobody acted on. Kept here instead: visible to a
    /// human reading the full transcript, without penalizing a clean final answer.
    /// </remarks>
    public IReadOnlyList<string> AbandonedReasoningWarnings { get; init; } = [];

    /// <summary>
    /// What this audit cost, split by model tier (SEC-31). Defaults to
    /// <see cref="AuditCost.None"/> — nothing measured — rather than to zero spend.
    /// </summary>
    public AuditCost Cost { get; init; } = AuditCost.None;

    /// <summary>
    /// The corpus snapshot this audit's knowledge actually came from (SEC-48).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Observed, not configured.</b> It is read off the chunks retrieval returned, so it
    /// records the corpus that answered rather than the one settings claimed would. Those can
    /// differ — a cluster re-ingested between accepting a job and running it is the obvious case —
    /// and when they do, the retrieved value is the one the citations rest on.
    /// </para>
    /// <para>
    /// Empty when nothing was retrieved, or when the corpus predates the payload field. That is
    /// distinguishable from a real version, which is the point: an audit that cannot name its
    /// corpus should not appear to.
    /// </para>
    /// </remarks>
    public string CorpusVersion { get; init; } = string.Empty;

    /// <summary>True when this audit can name the corpus its citations came from.</summary>
    public bool HasCorpusVersion => !string.IsNullOrWhiteSpace(CorpusVersion);

    /// <summary>Non-negotiable framing per AID-01 section 7.</summary>
    public string Disclaimer =>
        "Prioritized draft audit for human review — not a verified verdict.";
}

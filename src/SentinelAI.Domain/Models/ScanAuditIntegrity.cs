using SentinelAI.Domain.Abstractions;

namespace SentinelAI.Domain.Models
{
    /// <summary>
    /// What the machine could check about one scan's own reasoning, recorded per scan.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The question this answers is "did that run behave", not "is the finding real".</b> Nothing
    /// here is a judgement about security. Every column is either something an agent reported about
    /// itself (how many rounds, whether its verdict parsed) or something checked mechanically
    /// against the graph the same scan built — never an LLM's opinion of another LLM.
    /// </para>
    /// <para>
    /// <b>Why it is stored rather than logged.</b> The SEC-50 edge check already ran on every
    /// debate and its results already decided whether a chain could reach <c>Validated</c> — and
    /// then went into a log line and a prose paragraph in the report summary. That is enough to
    /// handle one scan and useless for the only questions worth asking: is the fabricated-edge rate
    /// going up, did the last model change make verdicts less readable, how many chains are we
    /// actually adjudicating. Those need rows.
    /// </para>
    /// <para>
    /// <b>Not shown to customers.</b> Read through an admin-only endpoint, and absent from the UI's
    /// wire types entirely. A customer reading "2 edge integrity warnings" on their own audit would
    /// reasonably conclude the product had told them their infrastructure was fine when it was not
    /// sure — when what actually happened is that a check caught a model overstating itself and the
    /// chain was capped accordingly, which is the system working.
    /// </para>
    /// </remarks>
    public class ScanAuditIntegrity : ITenantOwned
    {
        public Guid Id { get; set; }

        public Guid TenantId { get; set; }

        public Guid ScanJobId { get; set; }

        // ---- what the debate did -------------------------------------------------------------

        /// <summary>False when the tenant's plan does not include adjudication.</summary>
        /// <remarks>
        /// Recorded so a run with no findings-about-chains can be told apart from a run where the
        /// debate happened and concluded nothing. Without it every free-tier scan would look like a
        /// debate that produced no verdict.
        /// </remarks>
        public bool Adjudicated { get; set; }

        /// <summary>The debate's own one-word outcome, stored by name.</summary>
        public string Outcome { get; set; } = string.Empty;

        public int Rounds { get; set; }

        /// <summary>Whether the closing verdict could be parsed at all.</summary>
        /// <remarks>
        /// The cheapest early warning there is that a model or a prompt has drifted: an unreadable
        /// verdict is not a chain being refuted, it is the referee having stopped speaking the
        /// agreed language.
        /// </remarks>
        public bool VerdictReadable { get; set; }

        public bool TerminatedByTurnCap { get; set; }

        /// <summary>The weakest join the debate reasoned across, stored by name.</summary>
        public string WeakestJoin { get; set; } = string.Empty;

        // ---- what the mechanical check found (SEC-50) ----------------------------------------

        /// <summary>
        /// Hops in the chain the Reporter actually reported that the graph does not support.
        /// </summary>
        /// <remarks>
        /// The number worth watching. Non-zero means an agent asserted a join between two nodes
        /// with no edge between them, in the chain a human is being asked to trust — caught by
        /// comparison against the graph, not by another model's say-so.
        /// </remarks>
        public int EdgeIntegrityWarnings { get; set; }

        /// <summary>The warnings themselves, newline separated. Empty on a clean debate.</summary>
        public string EdgeIntegrityDetail { get; set; } = string.Empty;

        /// <summary>
        /// The same check, for reasoning the Reporter considered and dropped.
        /// </summary>
        /// <remarks>
        /// Counted separately and deliberately not added to the total. A candidate path an agent
        /// floated and abandoned is not evidence against the chain it finally reported — folding
        /// the two together would penalise a clean answer for a discarded draft.
        /// </remarks>
        public int AbandonedReasoningWarnings { get; set; }

        public string AbandonedReasoningDetail { get; set; } = string.Empty;

        // ---- what the corpus answered ---------------------------------------------------------

        /// <summary>Findings the retrieval stage tried to ground.</summary>
        public int RetrievalFindings { get; set; }

        /// <summary>How many came back with a chunk.</summary>
        public int RetrievalGrounded { get; set; }

        /// <summary>Grounding coverage as a whole percentage, floored.</summary>
        public int CoveragePercent { get; set; }

        /// <summary>Retrieval modes that never fired, comma separated. Empty when all did.</summary>
        public string ModesThatDidNotFire { get; set; } = string.Empty;

        // ---- what the graph stage produced -----------------------------------------------------

        public int CandidateChains { get; set; }

        /// <summary>
        /// Chains the debate actually reached a status on.
        /// </summary>
        /// <remarks>
        /// Almost always one, and that is the point of recording it. The debate reasons over the
        /// single highest-priority candidate, so every other chain stays <c>candidate</c> — true,
        /// and invisible unless somebody counts. "1 adjudicated of 9" is a product decision worth
        /// being able to see rather than an implementation detail buried in a writer.
        /// </remarks>
        public int ChainsAdjudicated { get; set; }

        // ---- provenance --------------------------------------------------------------------------

        /// <summary>The corpus version that actually answered, as observed from the chunks.</summary>
        public string CorpusVersion { get; set; } = string.Empty;

        /// <summary>
        /// Which version of these checks produced the row.
        /// </summary>
        /// <remarks>
        /// Earns its column the first time somebody compares two months of records: without it, a
        /// change in what is measured is indistinguishable from a change in what is being measured.
        /// </remarks>
        public int HarnessVersion { get; set; }

        public DateTime CreatedAt { get; set; }

        public ScanJob? ScanJob { get; set; }
    }
}

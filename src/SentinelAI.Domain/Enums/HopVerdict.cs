namespace SentinelAI.Domain.Enums;

/// <summary>
/// What Blue's validation turn actually said about one hop of a chain (AID-01 §3.3).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is not a <c>bool</c>.</b> <c>ChainHop.BlueValidated</c> used to be one, and a
/// <c>false</c> in that column answered four different questions with the same word: no debate
/// has run yet, Blue ran but never mentioned this hop, Blue said it could not tell, and Blue
/// positively contradicted it. The read API served that <c>false</c> to the dashboard, which
/// rendered "Blue validated 0 of N steps" on every chain ever produced — a sentence that read as
/// a finding when it was really an unpopulated column (audit 42-A).
/// </para>
/// <para>
/// Blue's own instructions (<c>BlueTeamExecutor.Instructions</c>) already make three of these a
/// closed vocabulary — CONFIRMED, UNRESOLVED, REFUTED — and are explicit that UNRESOLVED is not
/// REFUTED: being unable to confirm a hop is not evidence against it. Collapsing that distinction
/// into a bool is exactly the mistake that instruction paragraph exists to prevent, so the column
/// keeps it.
/// </para>
/// <para>
/// The two members Blue does not write are the honest ones. <see cref="Unassessed"/> is the
/// state a hop is born in and means <em>nobody has looked</em>. <see cref="Unattributed"/> means
/// Blue's turn <em>was</em> read and no verdict in it could be tied to this hop — a hop it
/// skipped, a line it wrote without naming the two nodes, or a line naming two verdicts at once.
/// Neither is a judgement about the hop, and neither may ever be shown as one.
/// </para>
/// <para>
/// Persisted by name via <c>HasConversion&lt;string&gt;()</c> like every other enum here, so
/// these ordinals are free to change.
/// </para>
/// </remarks>
public enum HopVerdict
{
    /// <summary>
    /// No debate has judged this hop. The state <c>CandidateChainWriter</c> writes: the graph
    /// stage found a path, and Red and Blue have not run over it yet.
    /// </summary>
    Unassessed = 0,

    /// <summary>
    /// Blue's turn was read, and none of it could be attributed to this hop. Distinct from
    /// <see cref="Unresolved"/>, which is Blue actively saying "the evidence cannot settle
    /// this" — here Blue said nothing this hop can be held to.
    /// </summary>
    Unattributed = 1,

    /// <summary>Blue: the configuration positively contradicts this hop.</summary>
    Refuted = 2,

    /// <summary>Blue: the evidence given cannot settle this hop either way.</summary>
    Unresolved = 3,

    /// <summary>Blue: the configuration shows this hop is real, and Blue named the evidence.</summary>
    Confirmed = 4,
}

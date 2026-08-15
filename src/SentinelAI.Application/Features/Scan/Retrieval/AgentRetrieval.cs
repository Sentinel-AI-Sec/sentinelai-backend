using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// SEC-23: which half of the corpus each agent reads.
/// </summary>
/// <remarks>
/// <para>
/// One shared corpus, split by <b>role</b> and never by tool. A Checkov finding and a Roslyn
/// finding about the same weakness resolve into the same two collections; what differs is who is
/// asking. That is the whole story: "attacker and defender reasoning are each grounded in the
/// right knowledge regardless of which tool found the issue."
/// </para>
/// <para>
/// <b>Why a per-tool index would be wrong</b>, since it is the obvious alternative: the corpus is
/// organised by what knowledge <em>is</em> — a technique, a mitigation, a weakness definition —
/// not by which scanner happened to notice the problem. Indexing per tool would mean a CWE-502
/// finding retrieved different knowledge depending on whether Roslyn or Trivy reported it, which
/// is a difference with no meaning behind it.
/// </para>
/// <para>
/// This maps role to <em>intent</em> rather than straight to a collection, so the mandatory
/// filter comes with it. "Blue reads defense" is not enough on its own — an unfiltered defense
/// query still returns CVE descriptions, because 26,283 NVD chunks outrank 172 OWASP ones for
/// any query (<c>PIPELINE_A_CONTEXT.md</c> §4). Going through <see cref="RetrievalIntent"/> means
/// the collection and the filter are chosen together and cannot come apart.
/// </para>
/// </remarks>
public static class AgentRetrieval
{
    /// <summary>
    /// The question this agent asks the corpus, or null when it does not read the corpus at all.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Red asks how an attack works</b> — ATT&amp;CK techniques and CAPEC patterns, from the
    /// offense collection. It is asserting exploit paths, so it needs the offensive vocabulary.
    /// </para>
    /// <para>
    /// <b>Blue asks how the weakness is remediated</b> — mitigations, from defense. Filtered on
    /// <c>content_type</c> rather than source because CWE and CAPEC both carry mitigations, and
    /// picking either source alone would drop half the remediation guidance in the corpus.
    /// </para>
    /// <para>
    /// <b>Orchestrator and Reporter return null, deliberately.</b> Neither reasons about new
    /// knowledge: the Orchestrator summarises the graph it was handed, and the Reporter
    /// adjudicates a transcript whose claims are already cited. Giving them a retrieval budget
    /// would spend it fetching chunks nothing then cites — and, worse, would let the Reporter
    /// introduce evidence the debate never argued over.
    /// </para>
    /// </remarks>
    public static RetrievalIntent? IntentFor(AgentRole role) => role switch
    {
        AgentRole.Red => RetrievalIntent.HowAnAttackerWould,
        AgentRole.Blue => RetrievalIntent.HowToFix,
        AgentRole.Orchestrator or AgentRole.Reporter => null,

        _ => throw new ArgumentOutOfRangeException(
            nameof(role), role, "No retrieval intent decided for this agent role."),
    };

    /// <summary>
    /// Which collection this agent reads, or null when it does not retrieve.
    /// </summary>
    /// <remarks>
    /// Derived from the intent rather than mapped separately, so the two can never disagree about
    /// where Blue's knowledge comes from.
    /// </remarks>
    public static KnowledgeCollection? CollectionFor(AgentRole role) =>
        IntentFor(role) is { } intent ? intent.Collection() : null;

    /// <summary>
    /// The agents that retrieve, in debate order. What a caller iterates to ground a scan.
    /// </summary>
    /// <remarks>
    /// Derived from <see cref="IntentFor"/> rather than listed by hand: adding a retrieving agent
    /// then means answering the question once, in one switch, instead of remembering to update a
    /// list that nothing would fail without.
    /// </remarks>
    public static IReadOnlyList<AgentRole> RetrievingRoles { get; } =
        [.. Enum.GetValues<AgentRole>().Where(r => IntentFor(r) is not null)];

    /// <summary>True when this agent grounds itself in the corpus.</summary>
    public static bool Retrieves(this AgentRole role) => IntentFor(role) is not null;
}

namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// What the caller wants to know, which is what decides the mandatory filter.
/// </summary>
/// <remarks>
/// Intent rather than agent name: SEC-23 maps Red to <see cref="HowAnAttackerWould"/> and Blue to
/// the defensive intents, but the corpus does not care who is asking. Keying the filter table on
/// the question keeps SEC-22 free of the agent vocabulary and lets the Reporter ask a defensive
/// question without pretending to be Blue.
/// </remarks>
public enum RetrievalIntent
{
    /// <summary>"How would an attacker do this?" — techniques and attack patterns.</summary>
    HowAnAttackerWould,

    /// <summary>"How do I fix this?" — remediation guidance.</summary>
    HowToFix,

    /// <summary>"How do I detect this?" — detection analytics.</summary>
    HowToDetect,

    /// <summary>"What does the standard say?" — OWASP guidance.</summary>
    WhatTheStandardSays,
}

/// <summary>
/// The filter each intent carries, and the collection it reads.
/// </summary>
/// <remarks>
/// <para>
/// This is <c>PIPELINE_A_CONTEXT.md</c> §4's table, in code:
/// </para>
/// <list type="table">
/// <item><term>how would an attacker do X</term><description>offense, source in (ATTACK, CAPEC)</description></item>
/// <item><term>how do I fix X</term><description>defense, content_type=mitigation</description></item>
/// <item><term>how do I detect X</term><description>defense, content_type=detection</description></item>
/// <item><term>what does the standard say</term><description>defense, source=OWASP</description></item>
/// </list>
/// <para>
/// Every row carries a filter. That is the point of having the table at all — there is no
/// "unfiltered" intent to reach for, so the mandatory-filtering rule is satisfied by the type
/// system rather than by remembering.
/// </para>
/// </remarks>
public static class RetrievalIntents
{
    /// <summary>Builds the filtered semantic query for an intent.</summary>
    public static SemanticQuery ToQuery(this RetrievalIntent intent, string text, int topK = SemanticQuery.DefaultTopK) =>
        intent switch
        {
            // Techniques and attack patterns, not the CVEs that would otherwise fill the page.
            RetrievalIntent.HowAnAttackerWould => new SemanticQuery(
                text, KnowledgeCollection.Offense,
                sources: [KnowledgeSource.Attack, KnowledgeSource.Capec],
                topK: topK),

            // content_type, not source: CWE and CAPEC both carry mitigations, and asking for
            // either source alone would drop half the remediation guidance in the corpus.
            RetrievalIntent.HowToFix => new SemanticQuery(
                text, KnowledgeCollection.Defense,
                contentTypes: [KnowledgeContentType.Mitigation],
                topK: topK),

            // ATT&CK's 1,758 detection chunks come from x-mitre-analytic objects. There is no
            // x_mitre_detection field in current releases — coding to that name yields zero
            // defensive content and no error (PIPELINE_A_CONTEXT.md §7).
            RetrievalIntent.HowToDetect => new SemanticQuery(
                text, KnowledgeCollection.Defense,
                contentTypes: [KnowledgeContentType.Detection],
                topK: topK),

            RetrievalIntent.WhatTheStandardSays => new SemanticQuery(
                text, KnowledgeCollection.Defense,
                sources: [KnowledgeSource.Owasp],
                topK: topK),

            _ => throw new ArgumentOutOfRangeException(
                nameof(intent), intent, "No retrieval filter defined for this intent."),
        };

    /// <summary>Which collection an intent reads. SEC-23 asserts Red hits offense and Blue defense.</summary>
    public static KnowledgeCollection Collection(this RetrievalIntent intent) =>
        intent == RetrievalIntent.HowAnAttackerWould ? KnowledgeCollection.Offense : KnowledgeCollection.Defense;
}

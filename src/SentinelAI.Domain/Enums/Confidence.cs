namespace SentinelAI.Domain.Enums;

/// <summary>
/// How much a join can be trusted (AID-01 section 3.3). Carried by every graph edge and by
/// every debate turn, so a chain can inherit its weakest link.
/// </summary>
/// <remarks>
/// Ordered weakest-first on purpose, and pinned by a test. <see cref="ConfidenceExtensions.Weakest"/>
/// is the rule callers should use; the ordering exists so that rule stays a one-liner rather
/// than a switch that can drift away from the design document.
/// <para>
/// Reordering these members is safe for the database — every enum in this assembly is
/// persisted by name via <c>HasConversion&lt;string&gt;()</c>, never by ordinal — but it
/// would silently invert the weakest-link rule, so a test guards it.
/// </para>
/// </remarks>
public enum Confidence
{
    /// <summary>The join could not be confirmed. Surfaces as "potential chain, unverified join".</summary>
    Unresolved = 0,

    /// <summary>Convention-based, e.g. an image-name match. Usable, but flagged for scrutiny.</summary>
    Inferred = 1,

    /// <summary>Confirmed against the real configuration.</summary>
    Certain = 2,
}

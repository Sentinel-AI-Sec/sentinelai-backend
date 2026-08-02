namespace SentinelAI.Domain.Enums;

/// <summary>
/// The weakest-link rule from AID-01 section 3.3, in one place.
/// </summary>
/// <remarks>
/// A chain is only as trustworthy as its least-confident join, so a single unresolved hop
/// marks the whole chain for human review. Both the debate (which reduces over a transcript)
/// and the graph (which reduces over a chain's edges) need this, so neither owns it.
/// </remarks>
public static class ConfidenceExtensions
{
    /// <summary>
    /// The least-confident value in the sequence, or <see cref="Confidence.Certain"/> when
    /// the sequence is empty — nothing asserted means nothing to doubt.
    /// </summary>
    public static Confidence Weakest(this IEnumerable<Confidence> confidences)
    {
        ArgumentNullException.ThrowIfNull(confidences);

        var weakest = Confidence.Certain;
        foreach (var c in confidences)
        {
            if (c < weakest) weakest = c;
        }

        return weakest;
    }

    /// <summary>Weakest-link over a projection, so callers need no intermediate Select.</summary>
    public static Confidence Weakest<T>(this IEnumerable<T> source, Func<T, Confidence> selector)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(selector);

        return source.Select(selector).Weakest();
    }
}

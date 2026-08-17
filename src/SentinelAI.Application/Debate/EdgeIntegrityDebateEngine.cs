using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Debate;

/// <summary>
/// Wraps the real <see cref="IDebateEngine"/> and mechanically checks Red's final assertion
/// against the resource graph's real edges on the way out (SEC-50).
/// </summary>
/// <remarks>
/// <para>
/// Same shape as <c>RedactingDebateEngine</c>, and for the same reason: a guard that every
/// caller has to remember to run is a guard someone eventually forgets to run. Decorating the
/// interface at registration means <c>POST /v1/scans/{id}/audit</c> and <c>POST /v1/debates</c>
/// both get it without either one knowing it exists.
/// </para>
/// <para>
/// This checks the last Red turn, the last Blue turn, and the Reporter's closing turn. Earlier
/// rounds may have asserted and been broken; that is the debate working, not something to flag.
/// Blue was added after Red-and-Reporter-only missed a live case: Blue "completed" a hop Red had
/// left unfinished (<c>N4 -&gt; deployed-as -&gt; (no direct edge, but)</c>) into a specific,
/// nonexistent pairing that the Reporter then repeated as the chain's own citation. Checking
/// Blue directly, not only through whatever the Reporter happens to repeat, closes that same
/// class of gap at its source instead of depending on it surviving one more hop.
/// </para>
/// <para>
/// Two independent checks run: <see cref="EdgeAssertionValidator.Validate"/> asks whether a node
/// <em>pair</em> an agent names is a real edge, in either direction.
/// <see cref="EdgeAssertionValidator.ValidateNodeLabels"/> asks a different question — whether an
/// inline annotation like <c>N65:code:orderapp</c> names the node the brief actually declared
/// <c>N65</c> to be. A hop can use a real, correctly-directed edge between two node numbers whose
/// identities were still misstated by the very message reporting them; the two checks catch
/// different lies and neither substitutes for the other.
/// </para>
/// <para>
/// <b>The Reporter's own text is checked separately from Red's and Blue's</b>, and the two
/// results land in different <see cref="DraftAudit"/> fields
/// (<see cref="DraftAudit.EdgeIntegrityWarnings"/> vs. <see cref="DraftAudit.AbandonedReasoningWarnings"/>).
/// A live run had Red assert two candidate paths in one turn — one fabricated, one entirely real —
/// and the Reporter reported only the real one. Treating every hop anywhere in the transcript as
/// equally load-bearing would have capped that genuinely valid chain at <c>Asserted</c> for
/// reasoning the debate itself already discarded. The Reporter's text is what a reader is
/// actually being asked to trust; that is the text <c>ChainOutcomeWriter</c> reads, and Red's or
/// Blue's fabrication is downgraded to informational once it fails to survive into that text.
/// A finding already reported by the Reporter is not repeated as "abandoned" even if Red or Blue
/// also named it.
/// </para>
/// <para>
/// A warning here never changes <see cref="DraftAudit.Outcome"/> or <see cref="DraftAudit.WeakestJoin"/>
/// — this is additive information for a human reader and for <c>ChainOutcomeWriter</c>, not a
/// second verdict overwriting the debate's own. Silently downgrading <c>Converged</c> to
/// <c>ChainBroken</c> would claim a certainty about <em>why</em> the chain is wrong that a
/// mismatched node pair alone does not support.
/// </para>
/// </remarks>
public sealed class EdgeIntegrityDebateEngine(
    IDebateEngine inner,
    ILogger<EdgeIntegrityDebateEngine> logger) : IDebateEngine
{
    public async Task<DraftAudit> RunAsync(ScanBrief brief, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(brief);

        var audit = await inner.RunAsync(brief, ct).ConfigureAwait(false);

        var lastRed = audit.Transcript.LastOrDefault(t => t.Role == AgentRole.Red);
        var lastBlue = audit.Transcript.LastOrDefault(t => t.Role == AgentRole.Blue);
        var reporter = audit.Transcript.LastOrDefault(t => t.Role == AgentRole.Reporter);

        var reported = CheckedFindings(brief.Context, reporter?.Content);

        var reasoningText = string.Join(
            '\n', new[] { lastRed?.Content, lastBlue?.Content }.Where(c => c is not null));
        var reasoning = CheckedFindings(brief.Context, reasoningText)
            // Already surfaced as a reported-chain warning — repeating it as "abandoned" would
            // both double-count it and understate that it made it into the actual output.
            .Where(f => !reported.Contains(f))
            .ToList();

        if (reported.Count == 0 && reasoning.Count == 0) return audit;

        if (reported.Count > 0)
        {
            logger.LogWarning(
                "Mechanical edge check for scan {ScanJobId}: {Count} issue(s) in the REPORTED "
                + "chain do not match the resource graph: {Warnings}",
                brief.ScanJobId, reported.Count, string.Join(" | ", reported));
        }

        if (reasoning.Count > 0)
        {
            logger.LogWarning(
                "Mechanical edge check for scan {ScanJobId}: {Count} issue(s) in Red/Blue's "
                + "reasoning did not survive into the reported chain: {Warnings}",
                brief.ScanJobId, reasoning.Count, string.Join(" | ", reasoning));
        }

        return audit with { EdgeIntegrityWarnings = reported, AbandonedReasoningWarnings = reasoning };
    }

    /// <summary>Both checks over one piece of text, or nothing when there is no text to check.</summary>
    private static List<string> CheckedFindings(string briefContext, string? text)
    {
        if (string.IsNullOrEmpty(text)) return [];

        return
        [
            .. EdgeAssertionValidator.UnconfirmedDescriptions(briefContext, text),
            .. EdgeAssertionValidator.ValidateNodeLabels(briefContext, text).Select(f => f.Describe()),
        ];
    }
}

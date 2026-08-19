using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Security;

/// <summary>
/// Wraps the real <see cref="IDebateEngine"/> and scans the brief one last time on its way to
/// the model (SEC-33).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="IngressRedactionGate"/> already cleans everything a bundle contributes, so in the
/// normal flow this decorator finds nothing — and that is the point. The acceptance criterion is
/// "no secret reaches the model", and the only place that can be enforced rather than argued is
/// the call itself. Every other guarantee is a claim about a path; this one is a property of the
/// boundary, and it holds for paths nobody has written yet.
/// </para>
/// <para>
/// Two live paths already bypass the gate. <c>POST /v1/debates</c> takes a brief as free text
/// straight from a caller, and <c>ScanBriefRenderer</c> folds in retrieved knowledge chunks that
/// never passed through ingest. Neither is a hypothetical: both reach a model provider, and
/// neither would be covered by a gate that only sits in the scan pipeline.
/// </para>
/// <para>
/// A hit here is logged at warning, because it means content reached the boundary that the
/// pipeline should already have cleaned — the redaction worked, but something upstream needs
/// looking at. The debate still runs, on the redacted brief: refusing to run would turn a
/// contained near-miss into an outage.
/// </para>
/// </remarks>
public sealed class RedactingDebateEngine(
    IDebateEngine inner,
    ISecretScanner scanner,
    ILogger<RedactingDebateEngine> logger) : IDecoratingDebateEngine
{
    /// <summary>The engine this one wraps, so a wiring test can assert the chain (SEC-48 note).</summary>
    public IDebateEngine Inner => inner;

    public Task<DraftAudit> RunAsync(ScanBrief brief, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(brief);

        var result = scanner.Scan(brief.Context);

        if (!result.HasSecrets)
            return inner.RunAsync(brief, ct);

        logger.LogWarning(
            "Ingress backstop: {Count} secret(s) were still in the brief for scan {ScanJobId} at "
            + "the model boundary and were redacted there ({Rules}). Nothing was sent unredacted, "
            + "but the upstream path that produced this text is not redacting",
            result.Matches.Count,
            brief.ScanJobId,
            string.Join(", ", result.Matches.Select(m => m.RuleId).Distinct()));

        return inner.RunAsync(brief with { Context = result.Redacted }, ct);
    }
}

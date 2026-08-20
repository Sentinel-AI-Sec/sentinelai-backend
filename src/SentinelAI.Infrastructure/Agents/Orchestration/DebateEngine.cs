using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Providers;
using SentinelAI.Infrastructure.Observability;

namespace SentinelAI.Infrastructure.Agents.Orchestration;

/// <summary>
/// The Agent Framework implementation of <see cref="IDebateEngine"/>.
/// </summary>
/// <remarks>
/// <para>
/// A <c>Workflow</c> may only be owned by one runner at a time, so this builds a fresh one
/// per call rather than caching it. That also keeps the engine safe to register as a
/// singleton and call concurrently — two scans never contend for the same workflow.
/// </para>
/// <para>
/// <see cref="DebateRunner"/> is still the richer surface: it exposes checkpoints, the
/// session id, live events, and resume. This wrapper is the narrow slice the Application
/// layer actually asked for.
/// </para>
/// </remarks>
public sealed class DebateEngine(
    IChatClientFactory clients,
    IOptions<DebateOptions> options,
    ModelPricing? pricing = null,
    TurnTracing? tracing = null) : IDebateEngine
{
    private readonly IChatClientFactory _clients =
        clients ?? throw new ArgumentNullException(nameof(clients));

    private readonly DebateOptions _options =
        options?.Value ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Token rates for the audit's cost breakdown (SEC-31). Optional so a caller constructing
    /// the engine directly — the demo, a test — still gets token counts without a price list.
    /// </summary>
    private readonly ModelPricing _pricing = pricing ?? ModelPricing.Unpriced;

    /// <summary>
    /// What each turn's span may record (SEC-36). Optional, and metadata-only when omitted, for
    /// the same reason <see cref="_pricing"/> is: a caller constructing the engine by hand gets
    /// the safe behaviour without having to know this parameter exists.
    /// </summary>
    private readonly TurnTracing _tracing = tracing ?? TurnTracing.MetadataOnly;

    public async Task<DraftAudit> RunAsync(ScanBrief brief, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(brief);

        // SEC-36's root span. Every turn span nests inside it, which is what lets a reader open
        // one trace and see the whole debate rather than four unrelated model calls. Null when
        // nothing is listening, and `using` handles that.
        using var trace = DebateTracing.StartDebate(brief.ScanJobId);

        var workflow = DebateWorkflow.Build(_clients, _options, _pricing, _tracing);
        var result = await new DebateRunner(workflow).RunAsync(brief, cancellationToken: ct)
            .ConfigureAwait(false);

        // Recorded before the throw below, so a debate that ended without an audit still leaves
        // a trace saying how far it got — which is the case someone is most likely to go
        // looking at a trace for.
        DebateTracing.RecordOutcome(trace, result.Turns.Count, result.Audit?.Converged ?? false);

        // The Reporter is reachable on every terminating path, so a missing audit means the
        // run failed rather than merely disagreeing. Surfacing it as an exception keeps the
        // caller from mistaking "crashed" for "found nothing".
        return result.Audit
            ?? throw new InvalidOperationException(
                $"Debate for scan '{brief.ScanJobId}' ended without an audit. "
                + $"{result.Turns.Count} turn(s) completed; "
                + $"{result.Checkpoints.Count} checkpoint(s) available for resume."
                + (result.Failures.Count > 0
                    ? $" Failure(s) reported by the workflow: {string.Join(" | ", result.Failures)}"
                    : " No failure event was reported by the workflow itself — check the model "
                      + "provider's own connectivity/rate-limit status directly."));
    }
}

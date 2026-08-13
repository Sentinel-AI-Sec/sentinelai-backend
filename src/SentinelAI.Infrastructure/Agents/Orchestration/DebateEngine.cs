using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Providers;

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
    ModelPricing? pricing = null) : IDebateEngine
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

    public async Task<DraftAudit> RunAsync(ScanBrief brief, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(brief);

        var workflow = DebateWorkflow.Build(_clients, _options, _pricing);
        var result = await new DebateRunner(workflow).RunAsync(brief, cancellationToken: ct)
            .ConfigureAwait(false);

        // The Reporter is reachable on every terminating path, so a missing audit means the
        // run failed rather than merely disagreeing. Surfacing it as an exception keeps the
        // caller from mistaking "crashed" for "found nothing".
        return result.Audit
            ?? throw new InvalidOperationException(
                $"Debate for scan '{brief.ScanJobId}' ended without an audit. "
                + $"{result.Turns.Count} turn(s) completed; "
                + $"{result.Checkpoints.Count} checkpoint(s) available for resume.");
    }
}

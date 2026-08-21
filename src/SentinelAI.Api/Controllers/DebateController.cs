using Microsoft.AspNetCore.Mvc;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;

namespace SentinelAI.Api.Controllers;

/// <summary>
/// Exposes the Red/Blue/Reporter debate over HTTP.
/// </summary>
/// <remarks>
/// Synchronous on purpose, and only for SEC-02. A live debate is four to seven sequential
/// model calls — 90–140s measured against NIM — which is far too long for a request thread
/// in production. The real pipeline enqueues a scan job and the client polls; this endpoint
/// exists so the agent stack can be exercised end to end through the API today.
/// </remarks>
[ApiController]
[Route("v1/debates")]
[Tags("Debate")]
public class DebateController(IDebateEngine engine) : ControllerBase
{
    /// <summary>
    /// Runs the Red/Blue/Reporter debate and returns a prioritized draft audit.
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<DebateResponse>> RunDebate(
        [FromBody] DebateRequest request, CancellationToken ct)
    {
        var brief = string.IsNullOrWhiteSpace(request.ResourceGraph)
            ? ScanBrief.Stub(request.ScanJobId ?? "api-scan")
            : new ScanBrief(request.ScanJobId ?? "api-scan", request.ResourceGraph);

        var audit = await engine.RunAsync(brief, ct);
        return Ok(DebateResponse.From(brief, audit));
    }

    /// <summary>
    /// Runs the debate against the built-in AID-01 fixture. No body required.
    /// </summary>
    [HttpPost("demo")]
    public async Task<ActionResult<DebateResponse>> RunDemoDebate(CancellationToken ct)
    {
        var brief = ScanBrief.Stub("demo-scan");
        var audit = await engine.RunAsync(brief, ct);
        return Ok(DebateResponse.From(brief, audit));
    }
}

/// <summary>Request body for <c>POST /v1/debates</c>.</summary>
/// <param name="ScanJobId">Correlation id for the scan. Defaults to <c>api-scan</c>.</param>
/// <param name="ResourceGraph">
/// The rendered resource graph the agents reason over. Omit to use the built-in fixture.
/// </param>
public sealed record DebateRequest(string? ScanJobId, string? ResourceGraph);

/// <summary>
/// The audit, flattened for the wire. <c>Outcome</c> and <c>Disclaimer</c> are surfaced
/// explicitly so a caller cannot render a result without the draft-not-verdict framing.
/// </summary>
public sealed record DebateResponse
{
    public required string ScanJobId { get; init; }
    public required string Outcome { get; init; }
    public required string WeakestJoin { get; init; }
    public required int Rounds { get; init; }
    public required int Turns { get; init; }
    public required bool TerminatedByTurnCap { get; init; }
    public required string Summary { get; init; }
    public required IReadOnlyList<TurnView> Transcript { get; init; }
    public required string Disclaimer { get; init; }

    /// <summary>
    /// SEC-50: hops or node labels in the Reporter's own reported chain that do not match a real
    /// edge in the resource graph. Non-empty means the reported chain itself is suspect — checked
    /// mechanically against the graph, not against another model's reading of it. Empty on a clean
    /// debate.
    /// </summary>
    public required IReadOnlyList<string> EdgeIntegrityWarnings { get; init; }

    /// <summary>
    /// SEC-50: the same mechanical check, but for hops that appeared only in Red's or Blue's raw
    /// reasoning and were not part of the chain the Reporter actually reported.
    /// </summary>
    public required IReadOnlyList<string> AbandonedReasoningWarnings { get; init; }

    /// <summary>What the audit cost, split by model tier (SEC-31).</summary>
    public required CostView Cost { get; init; }

    public static DebateResponse From(ScanBrief brief, DraftAudit audit) =>
        new()
        {
            ScanJobId = brief.ScanJobId,
            Outcome = audit.Outcome.ToString(),
            WeakestJoin = audit.WeakestJoin.ToString(),
            Rounds = audit.Rounds,
            Turns = audit.Transcript.Count,
            TerminatedByTurnCap = audit.TerminatedByTurnCap,
            Summary = audit.Summary,
            Transcript = [.. audit.Transcript.Select(t => TurnView.From(t, brief.Context))],
            Disclaimer = audit.Disclaimer,
            EdgeIntegrityWarnings = audit.EdgeIntegrityWarnings,
            AbandonedReasoningWarnings = audit.AbandonedReasoningWarnings,
            Cost = CostView.From(audit.Cost),
        };

    /// <param name="Tier">Which tier the turn was routed to — <c>High</c> or <c>Cheap</c>.</param>
    /// <param name="Content">
    /// The turn exactly as the agent wrote it, after <c>TranscriptText.Clean</c> removed the
    /// scratchpad and the markdown. Still sent in full even when <paramref name="Display"/> is
    /// populated: the structure is a reading of this text, and a reading a caller cannot check
    /// against the original is one it has to take on faith.
    /// </param>
    /// <param name="Display">
    /// The same turn taken apart into what it claimed — the hops with the graph's own node
    /// names, Blue's verdict on each, the grounded ATT&amp;CK id, and the deterministic edge
    /// check's answer. Every field may be empty; all of them empty means the agent wrote prose
    /// that could not be structured, and the caller should render <paramref name="Content"/>
    /// alone. See <see cref="TurnPresenter"/>.
    /// </param>
    public sealed record TurnView(
        string Role,
        int Round,
        string Confidence,
        string Tier,
        long Tokens,
        string Content,
        TurnDisplay Display)
    {
        public static TurnView From(DebateTurn t, string briefContext) =>
            new(t.Role.ToString(), t.Round, t.Confidence.ToString(), t.Tier.ToString(),
                t.Usage.TotalTokens, t.Content, TurnPresenter.Present(briefContext, t));
    }

    /// <summary>
    /// The cost figure, flattened for the wire.
    /// </summary>
    /// <remarks>
    /// <c>Rated</c> and <c>Measured</c> are surfaced rather than dropped because a total of
    /// zero has three different meanings — no model was called, the provider reported no
    /// usage, or nobody configured a price — and a caller that cannot tell them apart will
    /// read the third as a free scan.
    /// </remarks>
    public sealed record CostView(
        string Currency,
        decimal Total,
        int ModelCalls,
        long TotalTokens,
        bool Rated,
        bool Measured,
        IReadOnlyList<TierView> ByTier)
    {
        public static CostView From(AuditCost cost) =>
            new(cost.Currency, cost.Total, cost.TotalCalls, cost.TotalUsage.TotalTokens,
                cost.FullyRated, cost.Measured, [.. cost.ByTier.Select(TierView.From)]);
    }

    public sealed record TierView(
        string Tier, int Calls, long InputTokens, long OutputTokens, decimal Cost, bool Rated)
    {
        public static TierView From(TierSpend s) =>
            new(s.Tier.ToString(), s.Calls, s.Usage.InputTokens, s.Usage.OutputTokens,
                s.Cost, s.Rated);
    }
}

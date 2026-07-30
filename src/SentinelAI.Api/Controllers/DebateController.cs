using Microsoft.AspNetCore.Mvc;
using SentinelAI.Application.Abstractions;
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
            Transcript = [.. audit.Transcript.Select(TurnView.From)],
            Disclaimer = audit.Disclaimer,
        };

    public sealed record TurnView(string Role, int Round, string Confidence, string Content)
    {
        public static TurnView From(DebateTurn t) =>
            new(t.Role.ToString(), t.Round, t.Confidence.ToString(), t.Content);
    }
}

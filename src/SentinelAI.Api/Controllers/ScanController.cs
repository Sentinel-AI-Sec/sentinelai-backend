using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Api.Problems;
using SentinelAI.Application.Features.Scan.Commands.Purge;
using SentinelAI.Application.Features.Scan.Commands.RunAudit;
using SentinelAI.Application.Features.Scan.Commands.RunGraph;
using SentinelAI.Application.Features.Scan.Commands.Submit;
using SentinelAI.Application.Features.Scan.Queries.GetById;
using SentinelAI.Application.Features.Scan.Queries.Read;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Api.Controllers;

/// <summary>
/// Ingests a scan bundle from the GitHub Action (SEC-13). Accepts, records provenance,
/// refuses application source, and returns 202 with a poll URL — the pipeline that actually
/// scans the bundle runs afterward, out of the request.
/// </summary>
[ApiController]
[Route("v1/scans")]
[Tags("Scans")]
[Authorize]
public class ScanController(ISender sender) : ControllerBase
{
    /// <summary>64 MB, matching <c>TarGzBundleInspector</c>'s own ingest limit — rejected
    /// here before the bytes are even buffered, not after.</summary>
    private const long MaxBundleBytes = 64L * 1024 * 1024;

    /// <summary>
    /// Submits a bundle for scanning. Multipart: a <c>metadata</c> text part (the runner's
    /// metadata.json) and a <c>bundle</c> file part (the <c>.tar.gz</c>).
    /// </summary>
    [HttpPost]
    [Consumes("multipart/form-data")]
    [RequestSizeLimit(MaxBundleBytes)]
    public async Task<IActionResult> Submit([FromForm] SubmitScanRequest request, CancellationToken ct)
    {
        await using var bundleStream = request.Bundle.OpenReadStream();

        var response = await sender.Send(new SubmitScanCommand(request.Metadata, bundleStream), ct);

        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>Polls a scan job — the poll URL <c>Submit</c>'s 202 response hands back.
    /// Any authenticated caller may use this; tenant isolation is what actually scopes it.</summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id, CancellationToken ct)
    {
        var response = await sender.Send(new GetScanJobQuery(id), ct);
        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>
    /// Runs the normalize → graph → candidate-chain stages over an already-ingested bundle and
    /// returns the chains (SEC-14…SEC-20).
    /// </summary>
    /// <remarks>
    /// Synchronous and manually triggered, like <c>POST /v1/debates/demo</c>: no queue-driven
    /// worker exists yet, so this is how the pipeline is exercised end to end through the API
    /// without a GitHub Action run. It is fast — parsing and graph traversal, no model calls —
    /// so blocking the request is fine here in a way it would not be for the debate.
    /// Requires <c>scan:write</c>: it writes graph, node and chain rows.
    /// </remarks>
    [HttpPost("{id:guid}/graph")]
    public async Task<IActionResult> RunGraphStage(Guid id, CancellationToken ct)
    {
        var response = await sender.Send(new RunGraphStageCommand(id), ct);
        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>
    /// Runs the retrieve → debate → report → retention stages over a job whose graph stage has
    /// already run, and returns what the audit produced (SEC-40 Route B).
    /// </summary>
    /// <remarks>
    /// The sibling of <c>POST /v1/scans/{id}/graph</c>, manually triggered for the same reason:
    /// there is no queue-driven worker yet. Without it the report stage is reachable only from
    /// tests, so <c>GET /v1/reports/{id}</c> could never return anything however correct it was.
    /// Requires <c>scan:write</c> — it writes a report and purges the bundle.
    /// </remarks>
    [HttpPost("{id:guid}/audit")]
    public async Task<IActionResult> RunAuditStage(Guid id, CancellationToken ct)
    {
        var response = await sender.Send(new RunAuditStageCommand(id), ct);
        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>Administratively purges a job's stored bundle ahead of retention. Admin
    /// role only — this deletes an artifact, not just reads one.</summary>
    [HttpPost("{id:guid}/purge")]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Purge(Guid id, CancellationToken ct)
    {
        var response = await sender.Send(new PurgeScanBundleCommand(id), ct);
        return StatusCode((int)response.StatusCode, response);
    }

    // ---- SEC-40: the read API -------------------------------------------------------------
    // These four differ from everything above in how they answer: bare snake_case JSON on
    // success (the shape SentinelAI_API_Design_V2.1.md fixes and the Angular screen is built
    // against) and RFC 7807 problem+json on failure, rather than the Response envelope. The
    // envelope is unwrapped here at the edge; the handlers still return Response like every
    // other feature, so the Application layer stays free of HTTP representation concerns.

    /// <summary>Provenance of the bundle the runner uploaded. Survives the bundle's purge.</summary>
    [HttpGet("{id:guid}/bundle")]
    public async Task<IActionResult> GetBundle(Guid id, CancellationToken ct) =>
        Render(await sender.Send(new GetBundleQuery(id), ct));

    /// <summary>
    /// A page of normalized findings. Filter with <c>?layer=</c> (code|dep|infra) and
    /// <c>?min_severity=</c> (0–4); page with <c>?cursor=</c> and <c>?limit=</c>.
    /// </summary>
    [HttpGet("{id:guid}/findings")]
    public async Task<IActionResult> GetFindings(
        Guid id,
        [FromQuery] string? cursor,
        [FromQuery] int? limit,
        [FromQuery] string? layer,
        [FromQuery(Name = "min_severity")] int? minSeverity,
        CancellationToken ct) =>
        Render(await sender.Send(new GetFindingsQuery(id, cursor, limit, layer, minSeverity), ct));

    /// <summary>
    /// The whole resource graph: nodes plus edges carrying their confidence tier.
    /// </summary>
    /// <remarks>
    /// Not paginated, deliberately. A page of a graph contains edges pointing at nodes that are
    /// not in it — the screen cannot render that, and a reader cannot interpret it. Bounded by a
    /// node cap instead; a graph over the cap is refused with a message rather than truncated
    /// into something that would draw as a smaller system than the one scanned.
    /// </remarks>
    [HttpGet("{id:guid}/graph")]
    public async Task<IActionResult> GetGraph(Guid id, CancellationToken ct) =>
        Render(await sender.Send(new GetGraphQuery(id), ct));

    /// <summary>A page of candidate exploit chains, each with its hops and weakest join.</summary>
    [HttpGet("{id:guid}/chains")]
    public async Task<IActionResult> GetChains(
        Guid id, [FromQuery] string? cursor, [FromQuery] int? limit, CancellationToken ct) =>
        Render(await sender.Send(new GetChainsQuery(id, cursor, limit), ct));

    /// <summary>
    /// Unwraps a successful <see cref="Response"/> to its bare payload, or renders the failure
    /// as RFC 7807.
    /// </summary>
    private IActionResult Render(Response response) =>
        response.IsSuccess
            ? Ok(response.Data)
            : ReadApiProblem.From(HttpContext, response);
}

/// <summary>The two multipart parts <c>POST /v1/scans</c> expects.</summary>
public sealed class SubmitScanRequest
{
    /// <summary>The runner's metadata.json, as its own part — read without decompressing
    /// the bundle first, so routing/auth can fail fast on a bad or oversized upload.</summary>
    public required string Metadata { get; init; }

    /// <summary>The bundle tarball, <c>bundle.tar.gz</c>.</summary>
    public required IFormFile Bundle { get; init; }
}

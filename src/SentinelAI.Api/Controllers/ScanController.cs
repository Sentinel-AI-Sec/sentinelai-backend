using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Application.Features.Scan.Commands.Purge;
using SentinelAI.Application.Features.Scan.Commands.Submit;
using SentinelAI.Application.Features.Scan.Queries.GetById;
using SentinelAI.Domain.Models;

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

    /// <summary>Administratively purges a job's stored bundle ahead of retention. Admin
    /// role only — this deletes an artifact, not just reads one.</summary>
    [HttpPost("{id:guid}/purge")]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Purge(Guid id, CancellationToken ct)
    {
        var response = await sender.Send(new PurgeScanBundleCommand(id), ct);
        return StatusCode((int)response.StatusCode, response);
    }
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

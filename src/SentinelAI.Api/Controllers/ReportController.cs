using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Api.Problems;
using SentinelAI.Application.Features.Scan.Queries.Read;

namespace SentinelAI.Api.Controllers;

/// <summary>
/// Reads a draft audit (SEC-40).
/// </summary>
/// <remarks>
/// Its own controller, and its own route root, because a report is addressed by <em>its</em> id
/// rather than by the scan's: <c>GET /v1/reports/{id}</c> is what the API design document
/// specifies, and it is what lets a report be linked to directly without the reader having to
/// know which scan produced it.
/// </remarks>
[ApiController]
[Route("v1/reports")]
[Tags("Reports")]
[Authorize]
public class ReportController(ISender sender) : ControllerBase
{
    /// <summary>
    /// One draft audit: its framing, summary, chains with per-chain confidence, citations and
    /// cost.
    /// </summary>
    /// <remarks>
    /// A report exists only if the submitter opted into retention (SEC-35), so <c>404</c> is a
    /// normal answer here rather than an error — it means the audit ran and, as asked, was not
    /// kept.
    /// </remarks>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id, CancellationToken ct)
    {
        var response = await sender.Send(new GetReportQuery(id), ct);

        return response.IsSuccess
            ? Ok(response.Data)
            : ReadApiProblem.From(HttpContext, response);
    }
}

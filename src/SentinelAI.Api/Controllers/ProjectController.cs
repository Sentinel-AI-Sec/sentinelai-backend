using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Application.Features.Project.Commands.Create;
using SentinelAI.Application.Features.Project.Queries.List;
using SentinelAI.Domain.Models;

namespace SentinelAI.Api.Controllers;

/// <summary>
/// Registers the repositories a tenant may submit scans for, and hands back the id the GitHub
/// Action passes as its <c>project-id</c> input.
/// </summary>
/// <remarks>
/// <para>
/// This controller is the missing first step of the product's primary path. <c>POST /v1/scans</c>
/// resolves <c>metadata.project_id</c> against a <c>projects</c> row the caller's tenant owns, and
/// until this existed nothing in <c>src/</c> ever created one — a tenant registered through
/// <c>POST /v1/auth/register</c> could reach every other endpoint and never start a scan, because
/// the only way to get a project was an <c>INSERT</c> run by hand.
/// </para>
/// <para>
/// Creation is admin-only for the same reason <c>POST /v1/scans/{id}/purge</c> is: it changes what
/// the tenant is, not what it has looked at. Listing is not, because reading which repositories
/// your own tenant scans is what a viewer needs in order to read a report at all.
/// </para>
/// </remarks>
[ApiController]
[Route("v1/projects")]
[Tags("Projects")]
[Authorize]
public class ProjectController(ISender sender) : ControllerBase
{
    /// <summary>
    /// Registers a repository. Returns <c>201</c> with the new project id, or <c>409</c> carrying
    /// the id this repository is already registered as — see <see cref="CreateProjectCommand"/>
    /// for why re-registration returns the existing id rather than creating a second project.
    /// </summary>
    [HttpPost]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Create([FromBody] CreateProjectCommand command, CancellationToken ct)
    {
        var response = await sender.Send(command, ct);
        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>
    /// Every project this tenant owns. Another tenant's projects are not filtered out of the
    /// result — they are never in it, because the only tenant the query knows is the one on the
    /// verified token.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var response = await sender.Send(new ListProjectsQuery(), ct);
        return StatusCode((int)response.StatusCode, response);
    }
}

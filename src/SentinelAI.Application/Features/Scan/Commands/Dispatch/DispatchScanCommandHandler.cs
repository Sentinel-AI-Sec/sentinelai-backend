using System.Net;
using System.Text.Json.Serialization;
using MediatR;
using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Premitives;
using ProjectEntity = SentinelAI.Domain.Models.Project;

namespace SentinelAI.Application.Features.Scan.Commands.Dispatch;

/// <summary>
/// Resolves a project to its repository and asks that repository's CI to scan a branch.
/// </summary>
/// <remarks>
/// <para>
/// <b>No scan job is created here, and none is returned.</b> GitHub answers a dispatch with
/// <c>204</c> and no identifier, and the scan job does not exist until the Action uploads its
/// bundle minutes later through <c>POST /v1/scans</c> — the same path a pull request takes. So
/// this endpoint's honest answer is "asked", not "started", and the console finds the job by
/// listing the project's scans rather than by being handed an id that would be a guess.
/// </para>
/// <para>
/// Returning a fabricated job id would be worse than returning none: the screen would poll an id
/// that never becomes real if CI refuses the run, and report a scan that is not happening.
/// </para>
/// </remarks>
public class DispatchScanCommandHandler(
    IUnitOfWork unitOfWork, ICallerContext caller, IScanDispatcher dispatcher)
    : IRequestHandler<DispatchScanCommand, Response>
{
    public async Task<Response> Handle(DispatchScanCommand request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        // A person's token, not the Action's. The machine token exists to *upload* a scan the
        // Action has already run; letting it ask CI to run another one is a loop with a scan
        // job at every turn of it.
        if (caller.Role is null)
            return await Response.FailureAsync(
                "this action requires a signed-in user", HttpStatusCode.Forbidden);

        if (!dispatcher.IsConfigured)
            return await Response.FailureAsync(
                "starting a scan from here is not configured for this deployment "
                + "(Scanning:GitHub:Token is empty)",
                HttpStatusCode.ServiceUnavailable);

        var tenantId = caller.TenantId.Value;

        // Scoped to the caller's tenant explicitly as well as by the query filter, so the read is
        // provably tenant-safe from this method alone.
        var projects = await unitOfWork.Repository<ProjectEntity>()
            .GetWhereAsync(p => p.Id == request.ProjectId && p.TenantId == tenantId);

        var project = projects.FirstOrDefault();

        // A project belonging to another tenant answers exactly as one that does not exist, which
        // is what stops this being a way to discover other tenants' project ids.
        if (project is null)
            return await Response.FailureAsync("no such project", HttpStatusCode.NotFound);

        var gitRef = string.IsNullOrWhiteSpace(request.GitRef)
            ? project.DefaultBranch
            : request.GitRef.Trim();

        if (string.IsNullOrWhiteSpace(gitRef))
            return await Response.FailureAsync(
                "this project has no default branch, so a branch has to be named",
                HttpStatusCode.BadRequest);

        var result = await dispatcher.DispatchAsync(project.RepoUrl, gitRef, ct);

        if (!result.Accepted)
            return await Response.FailureAsync(
                result.Reason ?? "could not start a scan", HttpStatusCode.BadGateway);

        return await Response.SuccessAsync(
            new DispatchScanResponse
            {
                ProjectId = project.Id,
                RepoUrl = project.RepoUrl,
                GitRef = gitRef,
            },
            "scan requested",
            HttpStatusCode.Accepted);
    }
}

/// <summary>What was asked for, echoed back so the screen can say it without guessing.</summary>
/// <remarks>
/// snake_case with explicit names, matching the rest of what the console reads. Carries no scan
/// job id — see the handler for why there isn't one to carry.
/// </remarks>
public sealed record DispatchScanResponse
{
    [JsonPropertyName("project_id")]
    public required Guid ProjectId { get; init; }

    [JsonPropertyName("repo_url")]
    public required string RepoUrl { get; init; }

    /// <summary>The branch actually dispatched — the project's default when none was named.</summary>
    [JsonPropertyName("git_ref")]
    public required string GitRef { get; init; }
}

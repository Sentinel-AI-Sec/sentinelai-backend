using System.Net;
using MediatR;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Project.Queries.GetById;

/// <summary>
/// Reads one project. See <see cref="GetProjectQuery"/> for why it exists alongside the list.
/// </summary>
/// <remarks>
/// Routed through <see cref="IScanJobRepository.GetProjectForTenantAsync"/> rather than a fresh
/// <c>Repository&lt;Project&gt;()</c> lookup. That method already answers exactly this question —
/// it is what <c>POST /v1/scans</c> uses to decide whether a tenant may submit against a project
/// id — so reusing it means the read and the write agree on what "this tenant's project" means by
/// construction rather than by two predicates that happen to match today.
/// </remarks>
public class GetProjectQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<GetProjectQuery, Response>
{
    public async Task<Response> Handle(GetProjectQuery request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        var project = await unitOfWork.ScanJobRepository
            .GetProjectForTenantAsync(request.ProjectId, caller.TenantId.Value, ct);

        if (project is null)
            return await Response.FailureAsync($"no project '{request.ProjectId}'", HttpStatusCode.NotFound);

        return await Response.SuccessAsync(ProjectResponse.From(project), "project", HttpStatusCode.OK);
    }
}

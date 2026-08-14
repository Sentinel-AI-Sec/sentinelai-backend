using System.Net;
using MediatR;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Premitives;
using ProjectEntity = SentinelAI.Domain.Models.Project;

namespace SentinelAI.Application.Features.Project.Queries.List;

/// <summary>
/// Lists the caller's tenant's projects. See <see cref="Commands.Create.CreateProjectCommandHandler"/>'s
/// remarks for why the entity is aliased.
/// </summary>
/// <remarks>
/// No role gate. Reading which repositories your own tenant has registered is what a viewer needs
/// to interpret a report, and the row carries nothing a member of the tenant should not see. The
/// write side is admin-only; that is the axis the distinction belongs on.
/// </remarks>
public class ListProjectsQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<ListProjectsQuery, Response>
{
    public async Task<Response> Handle(ListProjectsQuery request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        // Filtered on the token's tenant explicitly, on top of the global query filter, for the
        // same reason ScanJobRepository does: SEC-32's own warning is that isolation which holds
        // only because of a filter somewhere else is isolation nobody can read at the call site.
        var projects = await unitOfWork.Repository<ProjectEntity>()
            .GetWhereAsync(p => p.TenantId == caller.TenantId.Value);

        var response = projects
            .OrderBy(p => p.RepoUrl, StringComparer.OrdinalIgnoreCase)
            .Select(ProjectResponse.From)
            .ToList();

        return await Response.SuccessAsync(response, "projects", HttpStatusCode.OK);
    }
}

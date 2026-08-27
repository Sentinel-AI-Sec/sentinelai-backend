using System.Net;
using MediatR;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Account.Queries.ListMembers;

/// <summary>
/// Lists the caller's tenant's members.
/// </summary>
/// <remarks>
/// <para>
/// <b>Admin-gated, unlike <c>ListProjectsQuery</c>, which is not.</b> The distinction is what the
/// row discloses. A project row names a repository the whole tenant already scans; a member row
/// names a colleague's email address and what they are permitted to do. The second is a directory
/// of who to phish and which of them can start a scan, which is not something a <c>viewer</c>
/// needs in order to read a report.
/// </para>
/// <para>
/// The gate is repeated here despite <c>[Authorize(Roles = Roles.Admin)]</c> on the action,
/// matching <c>DeleteAccountCommandHandler</c> and every other role-gated handler in this
/// codebase: the handler stays provably correct read on its own, rather than depending on an
/// attribute the reader has to go and confirm.
/// </para>
/// </remarks>
public sealed class ListMembersQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<ListMembersQuery, Response>
{
    public async Task<Response> Handle(ListMembersQuery request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        if (caller.Role != Roles.Admin)
            return await Response.FailureAsync(
                "listing members requires the admin role", HttpStatusCode.Forbidden);

        var tenantId = caller.TenantId.Value;

        // Filtered on the token's tenant explicitly, on top of the global query filter, for the
        // reason ListProjectsQueryHandler gives: isolation that holds only because of a filter
        // declared somewhere else is isolation nobody can verify at the call site.
        var members = await unitOfWork.Repository<User>()
            .GetTableAsNotTracked()
            .Where(u => u.TenantId == tenantId)
            .OrderBy(u => u.Email)
            .ToListAsync(ct);

        var response = members.Select(MemberResponse.From).ToList();

        return await Response.SuccessAsync(response, "members", HttpStatusCode.OK);
    }
}

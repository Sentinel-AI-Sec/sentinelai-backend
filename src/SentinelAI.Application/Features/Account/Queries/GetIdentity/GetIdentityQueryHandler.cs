using System.Net;
using MediatR;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Account.Queries.GetIdentity;

/// <summary>
/// Resolves the caller into an <see cref="IdentityResponse"/>.
/// </summary>
/// <remarks>
/// <para>
/// No scope gate. Every authenticated caller may ask who they are, including a machine token —
/// gating this would mean a token with the wrong scopes could not be told <em>which</em> scopes it
/// is missing, which is the one question this endpoint exists to answer.
/// </para>
/// <para>
/// The tenant is looked up by the token's tenant id and the user by the token's user id, with no
/// path that reads either from a request. <see cref="Tenant"/> is not
/// <see cref="ITenantOwned"/> — it is the thing tenancy is about — so no global query filter
/// applies to it and the id in the predicate is the only thing scoping this read. That is why it
/// comes from <see cref="ICallerContext"/> and nowhere else.
/// </para>
/// </remarks>
public class GetIdentityQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<GetIdentityQuery, Response>
{
    public async Task<Response> Handle(GetIdentityQuery request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        var tenantId = caller.TenantId.Value;

        var tenant = await unitOfWork.Repository<Tenant>()
            .GetTableAsNotTracked()
            .FirstOrDefaultAsync(t => t.Id == tenantId, ct);

        // A verified token whose tenant no longer exists means the account was deleted (SEC-35)
        // while the token was still inside its lifetime. 401, not 404: the correct client
        // response is to stop using this token, not to retry or to show an empty profile.
        if (tenant is null)
            return await Response.FailureAsync("this account no longer exists", HttpStatusCode.Unauthorized);

        User? user = null;
        if (caller.UserId is { } userId)
        {
            user = await unitOfWork.Repository<User>()
                .GetTableAsNotTracked()
                .FirstOrDefaultAsync(u => u.Id == userId && u.TenantId == tenantId, ct);
        }

        // Probed against the token, not mapped from the role — see IdentityResponse's remarks.
        var scopes = AuthScopes.All.Where(caller.HasScope).ToList();

        return await Response.SuccessAsync(
            IdentityResponse.From(tenant, user, caller.Role, scopes), "account", HttpStatusCode.OK);
    }
}

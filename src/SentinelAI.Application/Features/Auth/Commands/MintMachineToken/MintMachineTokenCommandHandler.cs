using System.Net;
using MediatR;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Auth.Commands.MintMachineToken;

/// <summary>
/// Issues a machine token for the caller's own tenant.
/// </summary>
/// <remarks>
/// <para>
/// <b>Admin only</b>, enforced at the controller the same way <c>POST /v1/projects</c> and
/// <c>DELETE /v1/account</c> are. Minting one changes what the tenant is — it creates a
/// credential that outlives every session — rather than reading what it has looked at.
/// </para>
/// <para>
/// <b>The caller cannot escalate through it.</b> The scopes are the operator set
/// (<c>scan:write</c>, <c>scan:read</c>, <c>report:read</c>) taken from
/// <see cref="RoleScopes.Machine"/> rather than requested in the body, and the minted token carries no
/// <c>role</c> claim at all, so it holds strictly less authority than the admin token used to ask
/// for it: it can upload a bundle and read the result, and every role-gated endpoint — bundle
/// purge, project registration, account deletion, and this endpoint itself — rejects it.
/// </para>
/// <para>
/// <b>It also cannot be revoked.</b> Nothing is stored, so there is no hash to revoke against the
/// way <c>/v1/auth/logout</c> revokes a refresh token; the token stays valid for its full lifetime
/// unless <c>Authentication:Jwt:SigningKey</c> is rotated, which invalidates every token this API
/// ever issued. That is a deliberate trade for a credential a CI runner has to present
/// unattended, and it is why the response says plainly that this is the only time it is readable.
/// </para>
/// </remarks>
public class MintMachineTokenCommandHandler(
    IUnitOfWork unitOfWork, ICallerContext caller, IJwtTokenIssuer tokenIssuer)
    : IRequestHandler<MintMachineTokenCommand, Response>
{
    public async Task<Response> Handle(MintMachineTokenCommand request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        var tenantId = caller.TenantId.Value;

        // Same check, and the same 401, as GetIdentityQueryHandler: a verified token whose tenant
        // no longer exists means the account was deleted while the token was inside its lifetime.
        // Minting a year-long credential for a tenant that is gone would outlive the deletion.
        var tenantExists = await unitOfWork.Repository<Tenant>()
            .GetTableAsNotTracked()
            .AnyAsync(t => t.Id == tenantId, ct);

        if (!tenantExists)
            return await Response.FailureAsync("this account no longer exists", HttpStatusCode.Unauthorized);

        // Fixed, not requested — see RoleScopes.Machine for which three and why each is needed.
        var scopes = RoleScopes.Machine;

        var token = tokenIssuer.IssueMachineToken(tenantId, scopes);

        var response = new MachineTokenResponse
        {
            Token = token,
            ExpiresAt = DateTime.UtcNow.Add(tokenIssuer.MachineTokenLifetime),
            Scopes = scopes,
            TenantId = tenantId,
        };

        return await Response.SuccessAsync(
            response, "machine token issued — it is not stored and cannot be shown again",
            HttpStatusCode.Created);
    }
}

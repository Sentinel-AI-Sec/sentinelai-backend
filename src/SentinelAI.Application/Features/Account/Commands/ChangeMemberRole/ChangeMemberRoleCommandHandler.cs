using System.Net;
using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Account.Commands.ChangeMemberRole;

/// <summary>
/// Assigns a role to another member of the caller's tenant, and ends that member's sessions so
/// the change actually takes effect.
/// </summary>
/// <remarks>
/// <para>
/// <b>An admin may not change their own role.</b> That single rule is also the whole
/// last-admin-lockout defence, and it is worth seeing why: only an admin can reach this handler,
/// and demoting an admin therefore requires a <em>different</em> admin, who is still an admin
/// afterwards. So a tenant can never reach zero admins, without this handler ever counting them.
/// A count-the-admins check would be the obvious alternative and is strictly worse — it races
/// (two of the last three admins demoting each other concurrently both read "there are others"),
/// and it needs a transaction to be correct at all.
/// </para>
/// <para>
/// <b>A target in another tenant is <c>404</c>, not <c>403</c>.</b> The lookup is scoped by
/// tenant, so a foreign user id is indistinguishable from one that never existed — which is the
/// point. Answering <c>403</c> would confirm the id names a real account somewhere, turning an
/// admin-held endpoint into an oracle for enumerating user ids across the whole install. This is
/// the same ordering <c>GetAuditIntegrityQueryHandler</c> uses for scans.
/// </para>
/// </remarks>
public sealed class ChangeMemberRoleCommandHandler(
    IUnitOfWork unitOfWork,
    ICallerContext caller,
    ILogger<ChangeMemberRoleCommandHandler> logger)
    : IRequestHandler<ChangeMemberRoleCommand, Response>
{
    public async Task<Response> Handle(ChangeMemberRoleCommand request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        if (caller.Role != Roles.Admin)
            return await Response.FailureAsync(
                "changing a member's role requires the admin role", HttpStatusCode.Forbidden);

        // A machine token has a tenant and no user id, so it cannot be "someone else" for the
        // purposes of the self-check below. It is already refused by the role gate above —
        // machine tokens carry no role — but the null case is handled rather than assumed,
        // because the self-check is the lockout defence and must not be reachable with a null.
        if (caller.UserId is not { } callerId)
            return await Response.FailureAsync(
                "changing a member's role requires a user token", HttpStatusCode.Forbidden);

        if (callerId == request.UserId)
            return await Response.FailureAsync(
                "you cannot change your own role; ask another admin to do it",
                HttpStatusCode.BadRequest);

        var tenantId = caller.TenantId.Value;

        // Tracked: this row is about to be written. Scoped on tenant explicitly as well as by the
        // global filter — see ListMembersQueryHandler.
        var member = await unitOfWork.Repository<User>()
            .GetTableAsTracked()
            .FirstOrDefaultAsync(u => u.Id == request.UserId && u.TenantId == tenantId, ct);

        if (member is null)
            return await Response.FailureAsync(
                $"no member '{request.UserId}' in this tenant", HttpStatusCode.NotFound);

        // Already there. Answered as success rather than as a conflict: the caller asked for a
        // state, and the state holds. Retrying a request whose response was lost should not
        // produce an error the second time.
        if (member.Role == request.Role)
            return await Response.SuccessAsync(
                MemberResponse.From(member), "member already holds this role", HttpStatusCode.OK);

        var previousRole = member.Role;
        member.Role = request.Role;

        // Revoking the member's refresh tokens is what makes this change mean something on a
        // realistic timescale. The role lives in the access token's claims, and nothing re-reads
        // the row until a token is reissued; leaving the refresh tokens alone would let a
        // demoted member keep renewing an admin access token for the refresh token's full 30-day
        // lifetime. Revoked, their next renewal fails and the sign-in that follows reads the new
        // role off the row.
        //
        // Their *current* access token still carries the old role until it expires — that is
        // inherent to stateless JWTs and is bounded by the access token lifetime, not by this.
        await unitOfWork.CompleteAsync();

        var revoked = await unitOfWork.RefreshTokenRepository
            .RevokeAllForUserAsync(member.Id, DateTime.UtcNow, ct);

        // Warning level, like account deletion: a privilege change is the event an audit asks
        // about after the fact, and nothing else in the system records that it happened.
        logger.LogWarning(
            "Role for user {TargetUserId} in tenant {TenantId} changed from {PreviousRole} to {NewRole} by admin {ActorUserId}; {RevokedCount} refresh token(s) revoked",
            member.Id, tenantId, previousRole, member.Role, callerId, revoked);

        return await Response.SuccessAsync(
            MemberResponse.From(member), "member role updated", HttpStatusCode.OK);
    }
}

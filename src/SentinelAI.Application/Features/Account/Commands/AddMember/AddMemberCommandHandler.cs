using System.Net;
using MediatR;
using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Account.Commands.AddMember;

/// <summary>
/// Moves a registered account into the caller's tenant, ends its sessions, and cleans up the
/// tenant it left if nobody remains in it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is a move and not an invitation.</b> <c>User.TenantId</c> is a single foreign key,
/// so an account is in exactly one tenant at a time. Registration always creates a fresh tenant
/// with the registrant as its admin, which means every registered address already owns a tenant —
/// there is no pool of tenant-less accounts waiting to be adopted. Joining here is therefore
/// always leaving somewhere, and the three questions below are all consequences of that.
/// </para>
/// <para>
/// <b>What happens to the tenant they leave.</b> If they were its only member it is purged: a
/// tenant with no users is unreachable forever, because every read is scoped by the tenant claim
/// on a user's token and no token can ever be issued for it again. Keeping it would mean holding
/// data nobody can ask for and nobody can delete, which is the state SEC-35 exists to prevent. If
/// other members remain, the tenant is left alone — but then the move is refused outright when
/// the account being taken is that tenant's <em>last admin</em>, because the people left behind
/// would keep their data and lose the only account able to administer it.
/// </para>
/// <para>
/// <b>An admin cannot add themselves.</b> Not as a special case — it falls out of the
/// already-a-member check, since the caller is by definition in the caller's tenant.
/// </para>
/// </remarks>
public sealed class AddMemberCommandHandler(
    IUnitOfWork unitOfWork,
    ICallerContext caller,
    ITenantPurge purge,
    ILogger<AddMemberCommandHandler> logger)
    : IRequestHandler<AddMemberCommand, Response>
{
    public async Task<Response> Handle(AddMemberCommand request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        if (caller.Role != Roles.Admin)
            return await Response.FailureAsync(
                "adding a member requires the admin role", HttpStatusCode.Forbidden);

        // A machine token carries a tenant and no user, so it could pass the tenant checks while
        // being nobody. Refused explicitly: bringing a person into an organisation is an act with
        // an actor, and the log line below would otherwise record it as having none.
        if (caller.UserId is not { } actorId)
            return await Response.FailureAsync(
                "adding a member requires a user token", HttpStatusCode.Forbidden);

        var tenantId = caller.TenantId.Value;

        // Normalised exactly as RegisterCommandHandler normalises before storing, so the lookup
        // matches what registration actually wrote. Comparing the raw input would make the
        // endpoint fail for any admin who typed a capital letter.
        var email = request.Email.Trim().ToLowerInvariant();

        var member = await unitOfWork.UserRepository.GetByEmailAsync(email, ct);

        // 404 rather than an offer to create one. This endpoint never provisions an account —
        // see AddMemberCommand — so "no such account" is the end of the road, not a branch.
        if (member is null)
            return await Response.FailureAsync(
                $"'{email}' is not a registered account", HttpStatusCode.NotFound);

        if (member.TenantId == tenantId)
            return await Response.FailureAsync(
                $"'{email}' is already a member of this tenant", HttpStatusCode.Conflict);

        var previousTenantId = member.TenantId;
        var membership = await unitOfWork.UserRepository.CountMembersAsync(previousTenantId, ct);

        // Everyone in their old tenant except the person being moved.
        var remaining = membership.Total - 1;

        if (remaining > 0 && member.Role == Roles.Admin && membership.Admins == 1)
        {
            return await Response.FailureAsync(
                $"'{email}' is the last admin of their current organisation and cannot be moved; "
                + "promote another member there first",
                HttpStatusCode.Conflict);
        }

        // Nobody left behind means the tenant is now unreachable — see the remarks.
        var purgePreviousTenant = remaining == 0;

        member.TenantId = tenantId;
        member.Role = request.Role;

        await unitOfWork.Repository<User>().UpdateAsync(member);
        await unitOfWork.CompleteAsync();

        // Their tokens carry the OLD tenant claim, which is the whole reason this cannot wait for
        // the purge below to take the rows with it: in the not-purged branch nothing else would
        // ever invalidate them, and a moved account would keep reading its former organisation's
        // data until the refresh token expired.
        var revoked = await unitOfWork.RefreshTokenRepository
            .RevokeAllForUserAsync(member.Id, DateTime.UtcNow, ct);

        // After the move and after the save, so the row now sitting in the caller's tenant is not
        // in the set this deletes.
        TenantPurgeReport? purged = null;
        if (purgePreviousTenant)
        {
            logger.LogWarning(
                "Tenant {PreviousTenantId} has no members left after moving user {UserId} and is being purged — this is irreversible",
                previousTenantId, member.Id);

            purged = await purge.PurgeAsync(previousTenantId, ct);
        }

        logger.LogWarning(
            "User {UserId} moved from tenant {PreviousTenantId} into tenant {TenantId} as {Role} by admin {ActorUserId}; {RevokedCount} session(s) revoked; previous tenant purged: {Purged}",
            member.Id, previousTenantId, tenantId, member.Role, actorId, revoked, purgePreviousTenant);

        return await Response.SuccessAsync(
            new AddMemberResponse
            {
                Member = MemberResponse.From(member),
                PreviousTenantId = previousTenantId,
                PreviousTenantPurged = purgePreviousTenant,
                PreviousTenantRowsDeleted = purged?.TotalRows ?? 0,
                SessionsRevoked = revoked,
            },
            "member added to this tenant",
            HttpStatusCode.OK);
    }
}

/// <summary>Receipt for a completed move.</summary>
/// <remarks>
/// It reports what happened to the account's previous tenant rather than only the member that
/// arrived, because one call can destroy an entire other tenant's data. An admin who is told only
/// "member added" has no way to know that happened, and no record of how much went with it.
/// </remarks>
public sealed record AddMemberResponse
{
    public required MemberResponse Member { get; init; }

    /// <summary>The tenant the account belonged to before this call.</summary>
    public required Guid PreviousTenantId { get; init; }

    /// <summary>Whether that tenant was left empty and therefore destroyed.</summary>
    public required bool PreviousTenantPurged { get; init; }

    /// <summary>Rows removed with it, across every table. Zero when it was not purged.</summary>
    public required int PreviousTenantRowsDeleted { get; init; }

    /// <summary>Live sessions ended, forcing the member to sign in again under this tenant.</summary>
    public required int SessionsRevoked { get; init; }
}

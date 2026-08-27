using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Application.Features.Account.Commands.AddMember;
using SentinelAI.Application.Features.Account.Commands.ChangeMemberRole;
using SentinelAI.Application.Features.Account.Commands.Delete;
using SentinelAI.Application.Features.Account.Queries.GetIdentity;
using SentinelAI.Application.Features.Account.Queries.ListMembers;
using SentinelAI.Domain.Models;

namespace SentinelAI.Api.Controllers;

/// <summary>
/// Account-level operations: who the caller is, who else is in their tenant and what those
/// people may do, and the right to be deleted (SEC-35).
/// </summary>
[ApiController]
[Route("v1/account")]
[Tags("Account")]
[Authorize]
public class AccountController(ISender sender) : ControllerBase
{
    /// <summary>
    /// Who the caller is signed in as: tenant, user, role, and the scopes this token actually
    /// holds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// No role gate, and no scope gate either. Every authenticated caller may ask who they are —
    /// gating this would mean a token with the wrong scopes could not be told which scopes it is
    /// missing, which is the question the endpoint exists to answer. It reads the caller and only
    /// the caller: there is no id parameter, so there is no id to substitute.
    /// </para>
    /// <para>
    /// The console currently learns all of this by decoding its own bearer token in the browser.
    /// That gets it the claims and nothing else — a JWT has no tenant name and no email — so the
    /// account screen can show a GUID and nothing a person recognises. See
    /// <see cref="IdentityResponse"/> for which fields come from the rows and which from the
    /// token, and why the permission fields deliberately come from the token.
    /// </para>
    /// </remarks>
    [HttpGet]
    public async Task<IActionResult> GetIdentity(CancellationToken ct)
    {
        var response = await sender.Send(new GetIdentityQuery(), ct);

        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>
    /// Every member of the caller's tenant, with the role each of them holds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Admin only, unlike <c>GET /v1/projects</c>, which any signed-in member may read. A project
    /// row names a repository the whole tenant already scans; a member row names a colleague's
    /// email address and what they are permitted to do — a directory of who to phish and which of
    /// them can start a scan. See <see cref="ListMembersQueryHandler"/>.
    /// </para>
    /// <para>
    /// Another tenant's members are not filtered out of the result — they are never in it, because
    /// the only tenant the query knows is the one on the verified token.
    /// </para>
    /// </remarks>
    [HttpGet("members")]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> ListMembers(CancellationToken ct)
    {
        var response = await sender.Send(new ListMembersQuery(), ct);

        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>
    /// Brings an existing account into the caller's tenant with the given role.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The address must already be registered</b> — an unknown one answers <c>404</c> rather
    /// than being provisioned. There is no password anywhere in this request, which is what stops
    /// an admin manufacturing an account whose credentials only they hold.
    /// </para>
    /// <para>
    /// An account belongs to one tenant at a time, so this is a move. Two refusals follow from
    /// that: <c>409</c> when they are already here, and <c>409</c> when they are the last admin of
    /// an organisation that still has other members, who would otherwise be stranded with data
    /// and nobody able to administer it.
    /// </para>
    /// <para>
    /// <b>If they were the only member of their old tenant, that tenant is destroyed</b> — a
    /// tenant with no users can never have a token issued for it again, so its data would be
    /// unreachable and undeletable forever. The response reports whether that happened and how
    /// many rows went with it. See <see cref="AddMemberCommandHandler"/>.
    /// </para>
    /// </remarks>
    [HttpPost("members")]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> AddMember(
        [FromBody] AddMemberCommand command, CancellationToken ct)
    {
        var response = await sender.Send(command, ct);

        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>
    /// Assigns a role — <c>admin</c>, <c>analyst</c> or <c>viewer</c> — to another member of the
    /// caller's tenant.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The target comes from the route, never the body, so there is exactly one place the most
    /// security-relevant field in the request can come from. A user id belonging to another
    /// tenant answers <c>404</c>, the same answer as an id that does not exist — see
    /// <see cref="ChangeMemberRoleCommandHandler"/> for why that is not merely tidy.
    /// </para>
    /// <para>
    /// <b>An admin cannot change their own role</b> (<c>400</c>). That is what makes a tenant with
    /// zero admins unreachable: demoting an admin takes a second admin, who remains one.
    /// </para>
    /// <para>
    /// The change takes effect when the member's next token is issued, not instantly: their live
    /// refresh tokens are revoked here, so the next renewal fails and the sign-in after it reads
    /// the new role. An access token already in their hands keeps its old claims until it expires.
    /// </para>
    /// </remarks>
    [HttpPatch("members/{id:guid}")]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> ChangeMemberRole(
        Guid id, [FromBody] ChangeMemberRoleCommand command, CancellationToken ct)
    {
        var response = await sender.Send(command with { UserId = id }, ct);

        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>
    /// Permanently deletes the calling account and every piece of data belonging to it —
    /// projects, scan jobs, stored bundles, findings, the resource graph, chains and reports.
    /// </summary>
    /// <remarks>
    /// <para>
    /// There is no request body and no id parameter: an account can only delete itself. That is
    /// the authorization model, not an omission — see <see cref="DeleteAccountCommand"/>.
    /// </para>
    /// <para>
    /// <b>This cannot be undone.</b> Nothing is soft-deleted or archived; a grace period would
    /// mean still holding data we said we destroyed.
    /// </para>
    /// </remarks>
    [HttpDelete]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Delete(CancellationToken ct)
    {
        var response = await sender.Send(new DeleteAccountCommand(), ct);

        return StatusCode((int)response.StatusCode, response);
    }
}

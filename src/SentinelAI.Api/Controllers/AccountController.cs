using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Application.Features.Account.Commands.Delete;
using SentinelAI.Application.Features.Account.Queries.GetIdentity;
using SentinelAI.Domain.Models;

namespace SentinelAI.Api.Controllers;

/// <summary>
/// Account-level operations. Currently the right to be deleted (SEC-35).
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

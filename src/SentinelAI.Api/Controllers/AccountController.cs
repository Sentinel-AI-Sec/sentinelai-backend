using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Application.Features.Account.Commands.Delete;
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

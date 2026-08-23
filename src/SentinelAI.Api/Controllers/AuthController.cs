using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Application.Features.Auth.Commands.Login;
using SentinelAI.Application.Features.Auth.Commands.Logout;
using SentinelAI.Application.Features.Auth.Commands.MintMachineToken;
using SentinelAI.Application.Features.Auth.Commands.Refresh;
using SentinelAI.Application.Features.Auth.Commands.Register;
using SentinelAI.Domain.Models;

namespace SentinelAI.Api.Controllers;

/// <summary>
/// Login/register (auth v1). No <c>[Authorize]</c> at the controller level — these are the
/// endpoints that hand out tokens in the first place, so requiring one to reach them would be
/// circular. <c>Logout</c> is gated purely by possessing a valid refresh token, not by a
/// still-current access token, since the whole point is to work even after the access token has
/// already expired.
/// </summary>
/// <remarks>
/// <see cref="MintMachineToken"/> is the one exception, and it carries its own
/// <c>[Authorize]</c> rather than the class doing so. It is not circular: it does not hand a
/// credential to someone with none, it trades a session you already hold for a longer-lived,
/// strictly weaker one for the same tenant. It lives here rather than on
/// <c>AccountController</c> because what it returns is a token, and every other line that mints
/// one is in this file.
/// </remarks>
[ApiController]
[Route("v1/auth")]
[Tags("Auth")]
public class AuthController(ISender sender) : ControllerBase
{
    /// <summary>Creates a brand-new tenant with the caller as its first admin.</summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterCommand command, CancellationToken ct)
    {
        var response = await sender.Send(command, ct);
        return StatusCode((int)response.StatusCode, response);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginCommand command, CancellationToken ct)
    {
        var response = await sender.Send(command, ct);
        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>Trades a still-valid refresh token for a new access/refresh pair. On
    /// success the presented token is revoked and replaced (rotation) — it can't be reused.</summary>
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenCommand command, CancellationToken ct)
    {
        var response = await sender.Send(command, ct);
        return StatusCode((int)response.StatusCode, response);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutCommand command, CancellationToken ct)
    {
        var response = await sender.Send(command, ct);
        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>
    /// Mints the long-lived token the GitHub Action authenticates with — the value that goes into
    /// the <c>SENTINELAI_MACHINE_TOKEN</c> repository secret.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Admin only</b>, for the same reason <c>POST /v1/projects</c> is: it changes what the
    /// tenant is — it creates a credential that outlives every session — rather than reading what
    /// it has looked at. There is no request body and no tenant parameter; the tenant comes off
    /// the caller's verified token, so there is nothing here a caller could substitute.
    /// </para>
    /// <para>
    /// <b>The token is returned once and is not stored.</b> Nothing persists it, so it cannot be
    /// fetched again and there is no hash to revoke it against the way <c>logout</c> revokes a
    /// refresh token — see <see cref="MintMachineTokenCommandHandler"/>. Losing it means minting
    /// another; invalidating one before its expiry means rotating the signing key.
    /// </para>
    /// <para>
    /// A machine token cannot mint another: it carries no <c>role</c> claim, so this endpoint
    /// rejects it like every other role-gated one.
    /// </para>
    /// </remarks>
    [HttpPost("machine-token")]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> MintMachineToken(CancellationToken ct)
    {
        var response = await sender.Send(new MintMachineTokenCommand(), ct);
        return StatusCode((int)response.StatusCode, response);
    }
}

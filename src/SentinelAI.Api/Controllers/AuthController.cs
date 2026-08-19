using MediatR;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Application.Features.Auth.Commands.Login;
using SentinelAI.Application.Features.Auth.Commands.Logout;
using SentinelAI.Application.Features.Auth.Commands.Refresh;
using SentinelAI.Application.Features.Auth.Commands.Register;

namespace SentinelAI.Api.Controllers;

/// <summary>
/// Login/register (auth v1). Deliberately no <c>[Authorize]</c> anywhere on this
/// controller — these are the endpoints that hand out tokens in the first place, so
/// requiring one to reach them would be circular. <c>Logout</c> is gated purely by
/// possessing a valid refresh token, not by a still-current access token, since the whole
/// point is to work even after the access token has already expired.
/// </summary>
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
}

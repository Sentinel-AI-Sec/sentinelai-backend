using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Auth.Commands.MintMachineToken;

/// <summary>
/// Mints the long-lived token the GitHub Action authenticates with
/// (<c>SENTINELAI_MACHINE_TOKEN</c>).
/// </summary>
/// <remarks>
/// <para>
/// Takes no parameters, exactly as <c>GetIdentityQuery</c> and <c>DeleteAccountCommand</c> take
/// none, and for the same reason: the tenant the token acts for is the caller's own, read off the
/// verified bearer token. There is no tenant id to pass, so there is no tenant id a caller could
/// substitute — that is the authorization model, not an omission. The scopes are fixed
/// (<see cref="MintMachineTokenCommandHandler"/> says which and why) rather than requested, so a
/// caller cannot ask for more than the Action needs.
/// </para>
/// <para>
/// Before this existed the value was minted out of band, by running a Python script against the
/// API's raw <c>Authentication:Jwt:SigningKey</c> — which meant handing whoever set up CI the one
/// secret that forges any token for any tenant. That is the practice this endpoint replaces.
/// </para>
/// </remarks>
public sealed record MintMachineTokenCommand : IRequest<Response>;

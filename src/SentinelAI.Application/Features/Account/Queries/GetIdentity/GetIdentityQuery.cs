using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Account.Queries.GetIdentity;

/// <summary>
/// The signed-in account: tenant, user, role and the scopes the token actually holds.
/// </summary>
/// <remarks>
/// Takes no parameters, exactly as <c>DeleteAccountCommand</c> takes none, and for the same
/// reason: an account can only read itself. There is no id to pass, so there is no id a caller
/// could substitute — that is the authorization model, not an omission.
/// </remarks>
public sealed record GetIdentityQuery : IRequest<Response>;

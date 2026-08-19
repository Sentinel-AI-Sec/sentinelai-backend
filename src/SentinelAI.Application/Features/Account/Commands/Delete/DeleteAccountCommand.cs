using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Account.Commands.Delete;

/// <summary>
/// Permanently deletes the calling account — the caller's whole tenant and everything in it
/// (SEC-35).
/// </summary>
/// <remarks>
/// <b>It deliberately takes no tenant id.</b> A caller can only ever delete their own account,
/// so there is no parameter an attacker could point at somebody else's data. Making the target
/// implicit removes an entire class of authorization bug from the most destructive operation in
/// the system: there is no request that could ask for the wrong tenant, so there is no check
/// that could be forgotten.
/// </remarks>
public sealed record DeleteAccountCommand : IRequest<Response>;

using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Account.Queries.ListMembers;

/// <summary>
/// Every user belonging to the caller's tenant.
/// </summary>
/// <remarks>
/// Takes no parameters, like <c>ListProjectsQuery</c> and for the same reason: the only scoping
/// input is the tenant on the verified token, so there is no field a caller could set to widen
/// the result past their own organisation.
/// </remarks>
public sealed record ListMembersQuery : IRequest<Response>;

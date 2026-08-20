using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Billing.Queries.GetSubscription;

/// <summary>
/// What the caller's own tenant is subscribed to.
/// </summary>
/// <remarks>
/// <para>
/// Takes no parameters, and that is the security property rather than an omission. The tenant
/// comes from the verified token, so there is no field a caller could set to ask about somebody
/// else's plan — the same rule <c>ListProjectsQuery</c> follows. Adding a tenant id here would
/// be adding the whole of a cross-tenant read.
/// </para>
/// <para>
/// Answers for a tenant that has never subscribed, rather than <c>404</c>. "No subscription" is
/// a plan — the free tier — and a screen that has to treat a missing resource as a business
/// state is a screen that will eventually treat a network failure as one too.
/// </para>
/// </remarks>
public sealed record GetSubscriptionQuery : IRequest<Response>;

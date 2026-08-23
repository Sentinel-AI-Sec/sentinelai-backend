using System.Net;
using MediatR;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Premitives;
using SubscriptionEntity = SentinelAI.Domain.Models.Subscription;
using SentinelAI.Application.Abstractions.Billing;

namespace SentinelAI.Application.Features.Billing.Queries.GetSubscription;

/// <summary>
/// Reads the caller's subscription through the ordinary repository, so tenant isolation applies.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately <em>not</em> <c>IBillingSubscriptionStore</c>. That exists for the webhook, which
/// has no tenant and has to step around the query filter; this path has a verified token and must
/// stay under it. The predicate below names the tenant as well, which is redundant with the
/// filter on purpose — a read of billing state should be provably scoped by looking at the
/// handler, not by knowing what <c>SentinelDbContext.OnModelCreating</c> does by reflection.
/// </para>
/// <para>
/// This never calls Stripe. The row is a cache of what Stripe's last signed webhook said, and a
/// screen that a customer refreshes should not cost an API call to a third party — nor should the
/// billing page break when Stripe is having an incident.
/// </para>
/// </remarks>
public sealed class GetSubscriptionQueryHandler(
    IUnitOfWork unitOfWork, ICallerContext caller, BillingSettings settings)
    : IRequestHandler<GetSubscriptionQuery, Response>
{
    public async Task<Response> Handle(GetSubscriptionQuery request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        var tenantId = caller.TenantId.Value;

        var subscriptions = await unitOfWork.Repository<SubscriptionEntity>()
            .GetWhereAsync(s => s.TenantId == tenantId);

        return await Response.SuccessAsync(
            SubscriptionView.From(subscriptions.FirstOrDefault(), settings.Provider),
            "subscription read",
            HttpStatusCode.OK);
    }
}

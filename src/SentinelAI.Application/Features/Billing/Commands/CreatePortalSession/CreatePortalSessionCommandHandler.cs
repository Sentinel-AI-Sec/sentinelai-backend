using System.Net;
using MediatR;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;
using SubscriptionEntity = SentinelAI.Domain.Models.Subscription;

namespace SentinelAI.Application.Features.Billing.Commands.CreatePortalSession;

/// <summary>
/// Hands the caller a one-time URL into Stripe's billing portal for their own tenant's customer.
/// </summary>
/// <remarks>
/// The customer id is read from the tenant's own row under the ordinary tenant filter, never
/// taken from the request. A portal session is full control over a Stripe customer — cards,
/// invoices, cancellation — so a customer id the caller could supply would be the ability to
/// cancel anyone's subscription and read their invoices.
/// </remarks>
public sealed class CreatePortalSessionCommandHandler(
    IUnitOfWork unitOfWork,
    ICallerContext caller,
    IBillingGateway billing,
    BillingSettings settings)
    : IRequestHandler<CreatePortalSessionCommand, Response>
{
    public async Task<Response> Handle(CreatePortalSessionCommand request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        // Admin-only for the same reason checkout is, and with a sharper edge: the portal can
        // cancel the organisation's subscription and download its invoices. Neither is something
        // a viewer should reach through a link this endpoint hands out.
        if (caller.Role != Roles.Admin)
            return await Response.FailureAsync(
                "managing billing requires the admin role", HttpStatusCode.Forbidden);

        if (!settings.IsConfigured)
        {
            return await Response.FailureAsync(
                "billing is not configured on this deployment", HttpStatusCode.ServiceUnavailable);
        }

        if (!settings.IsAllowedReturnUrl(request.ReturnUrl))
        {
            return await Response.FailureAsync(
                "returnUrl must be on an origin this deployment is configured to return to",
                HttpStatusCode.BadRequest);
        }

        var tenantId = caller.TenantId.Value;

        var subscriptions = await unitOfWork.Repository<SubscriptionEntity>()
            .GetWhereAsync(s => s.TenantId == tenantId);

        var customerId = subscriptions.FirstOrDefault()?.StripeCustomerId;

        if (string.IsNullOrWhiteSpace(customerId))
        {
            // 400 rather than 404: the tenant exists and so does billing — there is simply
            // nothing to manage yet, because a Stripe customer is only created by starting a
            // checkout. Saying so lets the UI point at the pricing page instead of reporting a
            // missing resource.
            return await Response.FailureAsync(
                "this organisation has no billing account yet — start a subscription first",
                HttpStatusCode.BadRequest);
        }

        try
        {
            var url = await billing.CreatePortalSessionAsync(customerId, request.ReturnUrl, ct);

            return await Response.SuccessAsync(
                new HostedSessionResponse { Url = url }, "portal session created", HttpStatusCode.OK);
        }
        catch (BillingGatewayException ex)
        {
            return await Response.FailureAsync(ex.Message, HttpStatusCode.BadGateway);
        }
    }
}

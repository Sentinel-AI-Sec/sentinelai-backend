using System.Net;
using MediatR;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;
using SubscriptionEntity = SentinelAI.Domain.Models.Subscription;

namespace SentinelAI.Application.Features.Billing.Commands.CreateCheckoutSession;

/// <summary>
/// Resolves the plan to a configured price, makes sure the tenant has a Stripe customer, and asks
/// Stripe for a hosted payment page.
/// </summary>
/// <remarks>
/// See <see cref="CreateCheckoutSessionCommand"/> for why the caller names a plan rather than a
/// price, and why nothing this handler does grants an entitlement.
/// </remarks>
public sealed class CreateCheckoutSessionCommandHandler(
    IUnitOfWork unitOfWork,
    ICallerContext caller,
    IBillingGateway billing,
    BillingSettings settings)
    : IRequestHandler<CreateCheckoutSessionCommand, Response>
{
    public async Task<Response> Handle(CreateCheckoutSessionCommand request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        // Buying a plan changes what the tenant is, not what it has looked at — the same test
        // that makes project creation and account deletion admin-only. It also closes the machine
        // -token case: the GitHub Action's token carries scan:write and no role at all, and a
        // token that exists to upload scanner output must not be able to spend the customer's
        // money.
        if (caller.Role != Roles.Admin)
            return await Response.FailureAsync(
                "starting a subscription requires the admin role", HttpStatusCode.Forbidden);

        if (!settings.IsConfigured || !settings.Plans.IsConfigured)
        {
            // 503, not 500: nothing is broken. This deployment has no Stripe account, which is a
            // legitimate configuration the UI already renders an honest state for.
            return await Response.FailureAsync(
                "billing is not configured on this deployment", HttpStatusCode.ServiceUnavailable);
        }

        // Parsed rather than re-validated: the validator has already refused anything that does
        // not parse, and duplicating the message here would create a second one to keep in step.
        var period = Enum.Parse<BillingPeriod>(request.Period, ignoreCase: true);

        var price = settings.Plans.Find(request.PlanId, period);

        if (price is null)
        {
            return await Response.FailureAsync(
                $"'{request.PlanId}' is not sold {period.ToString().ToLowerInvariant()} on this deployment",
                HttpStatusCode.BadRequest);
        }

        // Checked before Stripe is contacted, so a rejected return URL costs nothing and creates
        // no orphaned session. See BillingSettings.IsAllowedReturnUrl for why an unchecked one is
        // an open redirect rather than a cosmetic issue.
        if (!settings.IsAllowedReturnUrl(request.SuccessUrl)
            || !settings.IsAllowedReturnUrl(request.CancelUrl))
        {
            return await Response.FailureAsync(
                "successUrl and cancelUrl must both be on an origin this deployment is configured "
                + "to return to", HttpStatusCode.BadRequest);
        }

        var tenantId = caller.TenantId.Value;

        var email = await ResolveCallerEmailAsync(tenantId);

        if (email is null)
        {
            return await Response.FailureAsync(
                "this token is not attached to a user, so there is no one to bill",
                HttpStatusCode.Forbidden);
        }

        var subscription = await FindOrCreateAsync(tenantId, ct);

        string customerId;

        try
        {
            customerId = await billing.GetOrCreateCustomerAsync(
                tenantId, email, subscription.StripeCustomerId, ct);
        }
        catch (BillingGatewayException ex)
        {
            return await Response.FailureAsync(ex.Message, HttpStatusCode.BadGateway);
        }

        // Saved before the session is created, not after. If this write is skipped, the next
        // attempt has no customer id to reuse and mints a second Stripe customer, splitting one
        // organisation's invoices across two — and the billing portal only ever shows whichever
        // one it was last handed. Persisting first means an abandoned checkout still leaves the
        // tenant with exactly one customer.
        subscription.StripeCustomerId = customerId;
        subscription.UpdatedAt = DateTime.UtcNow;
        await unitOfWork.CompleteAsync();

        try
        {
            var url = await billing.CreateCheckoutSessionAsync(
                new CheckoutSessionRequest
                {
                    CustomerId = customerId,
                    PriceId = price.PriceId,
                    Quantity = request.Quantity ?? 1,
                    SuccessUrl = request.SuccessUrl,
                    CancelUrl = request.CancelUrl,
                    TenantId = tenantId,
                },
                ct);

            return await Response.SuccessAsync(
                new HostedSessionResponse { Url = url }, "checkout session created", HttpStatusCode.OK);
        }
        catch (BillingGatewayException ex)
        {
            return await Response.FailureAsync(ex.Message, HttpStatusCode.BadGateway);
        }
    }

    /// <summary>
    /// The email Stripe should bill, taken from the caller's own user row.
    /// </summary>
    /// <remarks>
    /// Read from the database rather than from a token claim, because the token is issued once
    /// and lives for an hour: a user who corrected their email would keep being billed at the old
    /// one until it expired. Null for a machine token, which has a tenant but no user — already
    /// refused above by the role check, and re-checked here so this method has one meaning.
    /// </remarks>
    private async Task<string?> ResolveCallerEmailAsync(Guid tenantId)
    {
        if (caller.UserId is not { } userId) return null;

        var users = await unitOfWork.Repository<User>()
            .GetWhereAsync(u => u.Id == userId && u.TenantId == tenantId);

        var email = users.FirstOrDefault()?.Email;

        return string.IsNullOrWhiteSpace(email) ? null : email;
    }

    /// <summary>
    /// The tenant's subscription row, created empty on first use.
    /// </summary>
    /// <remarks>
    /// Created here — before anything is paid for — because this row is what remembers the Stripe
    /// customer id, and the customer exists from the first checkout attempt onward. A row holding
    /// a customer id and <see cref="SubscriptionStatus.None"/> is the normal state of a tenant
    /// that opened the payment page and closed it, and it is what stops the next attempt creating
    /// a second Stripe customer.
    /// </remarks>
    private async Task<SubscriptionEntity> FindOrCreateAsync(Guid tenantId, CancellationToken ct)
    {
        var repository = unitOfWork.Repository<SubscriptionEntity>();

        var existing = await repository.GetWhereAsync(s => s.TenantId == tenantId);

        if (existing.FirstOrDefault() is { } subscription) return subscription;

        var created = new SubscriptionEntity
        {
            Id = Guid.CreateVersion7(),

            // From the verified token, never from the request body — SEC-32. A tenant id the
            // caller could supply is the whole of billing somebody else's organisation.
            TenantId = tenantId,
            Status = SubscriptionStatus.None,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
        };

        await repository.AddAsync(created);
        await unitOfWork.CompleteAsync();

        return created;
    }
}

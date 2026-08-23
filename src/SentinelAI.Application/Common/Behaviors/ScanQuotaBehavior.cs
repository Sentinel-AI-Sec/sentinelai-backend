using System.Net;
using MediatR;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Common.Behaviors;

/// <summary>
/// Marks a command that spends one unit of the tenant's daily scan quota.
/// </summary>
/// <remarks>
/// A marker rather than a check inside each handler, so <see cref="ScanQuotaBehavior{TRequest,
/// TResponse}"/> is constrained to it and MediatR resolves the behavior only for the commands that
/// carry it. Nothing to remember at a call site, and no runtime type test.
/// </remarks>
public interface IQuotaConsuming;

/// <summary>
/// Refuses a scan submission once the tenant has spent its plan's daily allowance.
/// </summary>
/// <remarks>
/// <para>
/// A pipeline behavior rather than a check in <c>SubmitScanCommandHandler</c>, for the reason
/// <c>ReadGuard</c> gives about the read endpoints: one place that cannot be skipped beats several
/// handlers that each remember. It is also the reason <c>ValidationBehavior</c> next door is a
/// behavior — a rule that lives in a handler is a rule the next handler will not have.
/// </para>
/// <para>
/// <b>Registered after <see cref="ValidationBehavior{TRequest, TResponse}"/>, and the order is
/// load-bearing.</b> Registration order is execution order, so validation runs first and a
/// malformed submission is a 400 that costs no quota. Reversed, a client sending garbage would burn
/// a customer's daily allowance on requests that never reached the handler.
/// </para>
/// <para>
/// <b>Counted at submit, not when the pipeline runs.</b> The worker claims jobs out of any request
/// and has nobody to return a 429 to, and the expensive part — buffering, hashing and storing a
/// bundle of up to 64 MB — has already happened by then. Refusing at the door is the only point
/// where the refusal is both cheap and deliverable. A scan accepted today and still queued tomorrow
/// simply runs: it was counted on the day it was accepted, and re-checking later would mean taking
/// a scan and then quietly not doing it.
/// </para>
/// </remarks>
public sealed class ScanQuotaBehavior<TRequest, TResponse>(
    ICallerContext caller,
    ITenantEntitlements entitlements,
    IScanQuotaCounter counter)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>, IQuotaConsuming
    where TResponse : Response, new()
{
    public async Task<TResponse> Handle(
        TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        // Passed straight through when there is no tenant to charge. This behavior runs before the
        // handler authorizes, and an unauthenticated submission has to come back as the handler's
        // 401 — answering 429 here would tell an anonymous caller they were rate limited rather
        // than that they were not signed in.
        if (caller.TenantId is not { } tenantId)
            return await next();

        // Nor when the caller is not allowed to submit at all. Authorization comes before
        // metering: a token without scan:write must come back as the handler's 403, and charging
        // it a scan first would both spend a customer's allowance on a request that was never
        // going to run and tell an unauthorized caller they were rate limited instead of refused.
        if (!caller.HasScope(AuthScopes.ScanWrite))
            return await next();

        var plan = await entitlements.ForTenantAsync(tenantId, cancellationToken);

        if (plan.HasUnlimitedScans)
            return await next();

        var now = DateTime.UtcNow;
        var decision = await counter.TryConsumeAsync(
            tenantId, plan.ScansPerDay, DateOnly.FromDateTime(now), cancellationToken);

        var today = DateOnly.FromDateTime(now);

        if (decision.Allowed)
        {
            var result = await next();

            // The unit was held for the duration of the request; hand it back if the handler
            // refused it. A refusal here is a submission that never became a scan -- malformed
            // metadata, a project this tenant does not own, a bundle carrying source. Charging for
            // those would let one misconfigured CI job spend a customer's whole day in two
            // requests and leave them rate limited with nothing to show for it.
            //
            // Only client errors. A 5xx may well have created the job before failing, and a 202 is
            // a scan: if it later dies in the pipeline it stays charged, which is the rule
            // IScanQuotaCounter sets out.
            if (IsClientRefusal(result.StatusCode))
                await counter.ReleaseAsync(tenantId, today, cancellationToken);

            return result;
        }

        return new TResponse
        {
            IsSuccess = false,
            StatusCode = HttpStatusCode.TooManyRequests,
            Message =
                $"the {plan.PlanId} plan allows {plan.ScansPerDay} scan"
                + (plan.ScansPerDay == 1 ? "" : "s")
                + " per day, and this organisation has used "
                + $"{decision.Used}. The allowance resets at midnight UTC.",
            // The seconds ride in the body because Response carries no headers and the Application
            // layer does not get to know about them -- the boundary ReadApiProblem keeps. The
            // controller lifts this onto Retry-After, which is what the API design document
            // specifies and what a CI runner will actually back off on.
            Data = new QuotaExceeded(
                plan.PlanId, plan.ScansPerDay, decision.Used, QuotaDecision.RetryAfterSeconds(now)),
        };
    }

    /// <summary>
    /// Whether the handler refused this request outright, as opposed to accepting it or failing
    /// while doing it.
    /// </summary>
    private static bool IsClientRefusal(HttpStatusCode status) =>
        (int)status is >= 400 and < 500 && status != HttpStatusCode.TooManyRequests;
}

/// <summary>
/// The body of a 429: what the limit was, what has been used, and when to come back.
/// </summary>
/// <remarks>
/// Named fields rather than a bare number so the screen can say "2 of 2 scans used today, resets at
/// midnight" instead of "rate limited", which tells a customer nothing they can act on — and in
/// particular does not tell them that upgrading is the fix.
/// </remarks>
public sealed record QuotaExceeded(string PlanId, int Limit, int Used, int RetryAfterSeconds);

namespace SentinelAI.Application.Abstractions.Billing;

/// <summary>
/// What a given tenant is currently entitled to.
/// </summary>
/// <remarks>
/// <para>
/// Takes a tenant id rather than reading the caller's, because the two callers need different
/// things: a request handler has a verified token to read it from, and the scan pipeline worker
/// runs out of any request and carries the tenant on the job row instead. The same split
/// <c>ScanPipelineRunner.RunAsync(scanJobId, tenantId)</c> already makes.
/// </para>
/// <para>
/// Resolves through <c>Tenant.PlanTier</c>, which the billing webhook is the only writer of. That
/// keeps entitlement downstream of what Stripe actually charged, rather than of what a checkout
/// request asked for.
/// </para>
/// </remarks>
public interface ITenantEntitlements
{
    /// <summary>
    /// The plan limits in force for this tenant. Falls back to the free tier for an unknown or
    /// missing tenant — never throws, because every caller is on a path that was doing something
    /// else and must not turn a lookup miss into a 500.
    /// </summary>
    Task<PlanEntitlements> ForTenantAsync(Guid tenantId, CancellationToken ct = default);
}

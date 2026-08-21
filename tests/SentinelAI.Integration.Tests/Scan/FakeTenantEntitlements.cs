using SentinelAI.Application.Abstractions.Billing;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// Fixed plan limits, for the pipeline tests that are about anything other than billing.
/// </summary>
/// <remarks>
/// Defaults to the enterprise tier — unlimited scans, adjudication on — because that is the
/// behaviour every test written before entitlements existed was asserting. A test that cares about
/// the gate says so explicitly with <see cref="WithoutDebate"/>, which keeps the entitlement out of
/// the setup noise of the twenty that do not.
/// </remarks>
internal sealed class FakeTenantEntitlements(PlanEntitlements? plan = null) : ITenantEntitlements
{
    private readonly PlanEntitlements _plan =
        plan ?? PlanEntitlementCatalog.For(PlanEntitlementCatalog.Enterprise);

    /// <summary>A tenant on a plan that does not include the Red/Blue debate.</summary>
    public static FakeTenantEntitlements WithoutDebate() =>
        new(PlanEntitlementCatalog.For(PlanEntitlementCatalog.Free));

    public Task<PlanEntitlements> ForTenantAsync(Guid tenantId, CancellationToken ct = default) =>
        Task.FromResult(_plan);
}

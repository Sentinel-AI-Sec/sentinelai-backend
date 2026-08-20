namespace SentinelAI.Domain.Enums;

/// <summary>
/// Which cadence a tenant bought. Stripe needs a distinct Price object for each, so this is
/// half of the key that resolves a plan to a price id — see <c>PlanCatalog</c>.
/// </summary>
public enum BillingPeriod
{
    Monthly,
    Annual
}

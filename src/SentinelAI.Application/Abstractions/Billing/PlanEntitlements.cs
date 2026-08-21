namespace SentinelAI.Application.Abstractions.Billing;

/// <summary>
/// What one plan actually lets a tenant do.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="int.MaxValue"/> means unlimited, rather than a nullable or a sentinel of its own.
/// It makes every consumer a plain <c>&lt;</c> comparison and removes the branch that a null would
/// add to each one — and the branch nobody writes is the one that ships as a bypass.
/// </para>
/// </remarks>
public sealed record PlanEntitlements
{
    public required string PlanId { get; init; }

    /// <summary>Scans a tenant may submit per UTC day.</summary>
    public required int ScansPerDay { get; init; }

    /// <summary>Repositories a tenant may register.</summary>
    public required int MaxProjects { get; init; }

    /// <summary>
    /// Whether the Red/Blue debate runs at all.
    /// </summary>
    /// <remarks>
    /// The one entitlement that changes what a scan <em>produces</em> rather than how many of them
    /// there may be. A scan without it still normalizes findings and builds the resource graph —
    /// what it does not get is adjudication, and the report has to say so rather than presenting an
    /// unadjudicated result as if a debate had cleared it.
    /// </remarks>
    public required bool DebateEnabled { get; init; }

    /// <summary>How long an opted-in draft audit is kept. 0 means never retain.</summary>
    public required int ReportRetentionDays { get; init; }

    /// <summary>Seats included before any are bought.</summary>
    public required int IncludedSeats { get; init; }

    public bool HasUnlimitedScans => ScansPerDay == int.MaxValue;

    public bool HasUnlimitedProjects => MaxProjects == int.MaxValue;
}

/// <summary>
/// The limits attached to each plan, and the only place they are written down.
/// </summary>
/// <remarks>
/// <para>
/// <b>Deliberately separate from <see cref="PlanCatalog"/>.</b> That type is an allowlist of what
/// may be <em>bought</em> — plan id and cadence to a Stripe Price — and its own remarks explain why
/// it must stay narrow. This is what a plan <em>grants</em> once bought. They are configured
/// differently too: prices are per-deployment and change with a Stripe account, whereas limits are
/// the product, identical everywhere it runs.
/// </para>
/// <para>
/// Compiled in rather than read from configuration, for the reason <c>RoleScopes</c> is: a
/// deployment that can rewrite its own limits is a deployment where the quota test proves nothing
/// about the product. The UI's <c>core/billing/plans.ts</c> displays these numbers and this is the
/// authority; the two are kept in step by <c>PlanEntitlementsTests</c>.
/// </para>
/// <para>
/// An unrecognised plan id resolves to <see cref="Free"/> rather than throwing, mirroring
/// <c>RoleScopes.For</c>: a tier string that no longer exists — a retired plan, a subscription
/// created by hand in the Stripe dashboard — must fail to the least privilege, never to the most,
/// and never to a 500 on an endpoint that was only trying to count a scan.
/// </para>
/// </remarks>
public static class PlanEntitlementCatalog
{
    public const string Free = "free";
    public const string Pro = "pro";
    public const string Max = "max";
    public const string Team = "team";
    public const string Enterprise = "enterprise";

    /// <summary>
    /// The plan id the first tier shipped under, before the ladder gained Pro and Max.
    /// </summary>
    /// <remarks>
    /// Kept as an alias rather than migrated away: it is written into existing <c>Tenant.PlanTier</c>
    /// rows and into any Stripe subscription created while it was the name. Dropping it would
    /// silently demote those tenants the next time their tier was read.
    /// </remarks>
    public const string LegacyDeveloper = "developer";

    private static readonly PlanEntitlements FreePlan = new()
    {
        PlanId = Free,
        ScansPerDay = 2,
        MaxProjects = 1,
        DebateEnabled = false,
        ReportRetentionDays = 7,
        IncludedSeats = 1,
    };

    private static readonly Dictionary<string, PlanEntitlements> Plans =
        new(StringComparer.OrdinalIgnoreCase)
        {
            [Free] = FreePlan,
            [LegacyDeveloper] = FreePlan with { PlanId = LegacyDeveloper },

            [Pro] = new PlanEntitlements
            {
                PlanId = Pro,
                ScansPerDay = 20,
                MaxProjects = 5,
                DebateEnabled = true,
                ReportRetentionDays = 30,
                IncludedSeats = 1,
            },

            [Max] = new PlanEntitlements
            {
                PlanId = Max,
                ScansPerDay = 100,
                MaxProjects = int.MaxValue,
                DebateEnabled = true,
                ReportRetentionDays = 365,
                IncludedSeats = 1,
            },

            [Team] = new PlanEntitlements
            {
                PlanId = Team,
                ScansPerDay = 100,
                MaxProjects = int.MaxValue,
                DebateEnabled = true,
                ReportRetentionDays = 365,
                IncludedSeats = 5,
            },

            [Enterprise] = new PlanEntitlements
            {
                PlanId = Enterprise,
                ScansPerDay = int.MaxValue,
                MaxProjects = int.MaxValue,
                DebateEnabled = true,
                ReportRetentionDays = int.MaxValue,
                IncludedSeats = int.MaxValue,
            },
        };

    /// <summary>Every plan the product defines, free first.</summary>
    public static IReadOnlyList<PlanEntitlements> All =>
        [Plans[Free], Plans[Pro], Plans[Max], Plans[Team], Plans[Enterprise]];

    /// <summary>
    /// The limits for a plan id. Never null, never throws — an unknown id is the free tier.
    /// </summary>
    public static PlanEntitlements For(string? planId) =>
        planId is not null && Plans.TryGetValue(planId.Trim(), out var plan) ? plan : FreePlan;

    /// <summary>Whether this id names a plan the product knows about.</summary>
    public static bool IsKnown(string? planId) =>
        planId is not null && Plans.ContainsKey(planId.Trim());
}

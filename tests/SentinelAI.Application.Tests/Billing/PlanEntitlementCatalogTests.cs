using SentinelAI.Application.Abstractions.Billing;

namespace SentinelAI.Application.Tests.Billing;

/// <summary>
/// The plan ladder, pinned.
/// </summary>
/// <remarks>
/// <para>
/// These numbers are displayed to customers by the UI's <c>core/billing/plans.ts</c> and enforced
/// here. Two copies of one table is a thing that drifts, and the failure when it does is a
/// customer who reads "20 scans a day", pays, and is refused at 10. This is the test that makes the
/// drift visible on this side; the file it mirrors names this type in its own header.
/// </para>
/// <para>
/// A pricing change is therefore a deliberate two-file edit with a failing test in between, which
/// is the point.
/// </para>
/// </remarks>
public class PlanEntitlementCatalogTests
{
    [Theory]
    [InlineData(PlanEntitlementCatalog.Free, 2, 1, false)]
    [InlineData(PlanEntitlementCatalog.Pro, 20, 5, true)]
    [InlineData(PlanEntitlementCatalog.Max, 100, int.MaxValue, true)]
    [InlineData(PlanEntitlementCatalog.Team, 100, int.MaxValue, true)]
    [InlineData(PlanEntitlementCatalog.Enterprise, int.MaxValue, int.MaxValue, true)]
    public void Every_tier_grants_what_the_pricing_page_says(
        string planId, int scansPerDay, int maxProjects, bool debate)
    {
        var plan = PlanEntitlementCatalog.For(planId);

        Assert.Equal(planId, plan.PlanId);
        Assert.Equal(scansPerDay, plan.ScansPerDay);
        Assert.Equal(maxProjects, plan.MaxProjects);
        Assert.Equal(debate, plan.DebateEnabled);
    }

    /// <summary>
    /// The free tier is the one that has to be right: it is what an unknown plan falls back to, so
    /// a mistake here is a mistake everywhere at once.
    /// </summary>
    [Fact]
    public void The_free_tier_allows_two_scans_a_day_and_no_debate()
    {
        var free = PlanEntitlementCatalog.For(PlanEntitlementCatalog.Free);

        Assert.Equal(2, free.ScansPerDay);
        Assert.False(free.DebateEnabled);
        Assert.False(free.HasUnlimitedScans);
    }

    /// <summary>
    /// Fails to the least privilege, mirroring <c>RoleScopes.For</c>. A retired plan id or a
    /// subscription created by hand in the Stripe dashboard must not resolve to unlimited, and must
    /// not throw on a path that was only trying to count a scan.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("platinum")]
    [InlineData("TEAM-2024")]
    public void An_unrecognised_plan_is_the_free_tier(string? planId)
    {
        var plan = PlanEntitlementCatalog.For(planId);

        Assert.Equal(PlanEntitlementCatalog.Free, plan.PlanId);
        Assert.Equal(2, plan.ScansPerDay);
        Assert.False(plan.DebateEnabled);
    }

    /// <summary>
    /// The id the first tier shipped under still resolves, and to the same limits. Dropping it
    /// would silently demote every tenant whose <c>PlanTier</c> still says <c>developer</c>.
    /// </summary>
    [Fact]
    public void The_legacy_developer_id_still_resolves_to_the_free_limits()
    {
        var legacy = PlanEntitlementCatalog.For(PlanEntitlementCatalog.LegacyDeveloper);
        var free = PlanEntitlementCatalog.For(PlanEntitlementCatalog.Free);

        Assert.True(PlanEntitlementCatalog.IsKnown(PlanEntitlementCatalog.LegacyDeveloper));
        Assert.Equal(free.ScansPerDay, legacy.ScansPerDay);
        Assert.Equal(free.MaxProjects, legacy.MaxProjects);
        Assert.Equal(free.DebateEnabled, legacy.DebateEnabled);
    }

    [Fact]
    public void Plan_ids_are_matched_without_regard_to_case()
    {
        Assert.Equal(PlanEntitlementCatalog.Pro, PlanEntitlementCatalog.For("PRO").PlanId);
        Assert.Equal(PlanEntitlementCatalog.Team, PlanEntitlementCatalog.For("  Team  ").PlanId);
    }

    /// <summary>
    /// Every rung is strictly better than the one below on the two limits a customer buys for.
    /// Not decoration: a ladder where an upgrade lowers a limit is a refund request.
    /// </summary>
    [Fact]
    public void The_ladder_never_goes_backwards()
    {
        var ladder = new[]
        {
            PlanEntitlementCatalog.For(PlanEntitlementCatalog.Free),
            PlanEntitlementCatalog.For(PlanEntitlementCatalog.Pro),
            PlanEntitlementCatalog.For(PlanEntitlementCatalog.Max),
        };

        for (var i = 1; i < ladder.Length; i++)
        {
            Assert.True(ladder[i].ScansPerDay > ladder[i - 1].ScansPerDay,
                $"{ladder[i].PlanId} does not allow more scans than {ladder[i - 1].PlanId}");
            Assert.True(ladder[i].MaxProjects >= ladder[i - 1].MaxProjects,
                $"{ladder[i].PlanId} allows fewer repositories than {ladder[i - 1].PlanId}");
            Assert.True(ladder[i].ReportRetentionDays >= ladder[i - 1].ReportRetentionDays,
                $"{ladder[i].PlanId} keeps audits for less time than {ladder[i - 1].PlanId}");
        }
    }

    [Fact]
    public void Only_the_free_tier_is_without_adjudication()
    {
        var withoutDebate = PlanEntitlementCatalog.All.Where(p => !p.DebateEnabled).ToList();

        var plan = Assert.Single(withoutDebate);
        Assert.Equal(PlanEntitlementCatalog.Free, plan.PlanId);
    }

    [Fact]
    public void Team_is_the_only_tier_that_includes_more_than_one_seat_by_default()
    {
        Assert.Equal(1, PlanEntitlementCatalog.For(PlanEntitlementCatalog.Pro).IncludedSeats);
        Assert.True(PlanEntitlementCatalog.For(PlanEntitlementCatalog.Team).IncludedSeats > 1);
    }
}

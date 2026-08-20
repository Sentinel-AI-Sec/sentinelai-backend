using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

/// <summary>
/// Storage shape for a tenant's subscription, and the two uniqueness rules that keep billing
/// state from forking.
/// </summary>
public class SubscriptionConfiguration : IEntityTypeConfiguration<Subscription>
{
    /// <summary>
    /// Stripe object ids. Documented as opaque strings with no published maximum; 255 is the
    /// length the Stripe libraries and every schema example in their docs use, and it is
    /// comfortably above the ~30 characters real ids run to.
    /// </summary>
    private const int StripeIdLength = 255;

    /// <summary>
    /// Matches the plan ids in the UI's <c>core/billing/plans.ts</c>, with room to spare. Bounded
    /// rather than unlimited because <c>Tenant.PlanTier</c> is compared against it.
    /// </summary>
    private const int PlanIdLength = 100;

    public void Configure(EntityTypeBuilder<Subscription> builder)
    {
        builder.Property(s => s.PlanId).HasMaxLength(PlanIdLength).IsRequired();

        // Stored by name, like every other enum here, so the column is readable in a query
        // window and the enum's ordinals stay free to change.
        builder.Property(s => s.Status).HasConversion<string>();
        builder.Property(s => s.Period).HasConversion<string>();

        builder.Property(s => s.StripeCustomerId).HasMaxLength(StripeIdLength);
        builder.Property(s => s.StripeSubscriptionId).HasMaxLength(StripeIdLength);
        builder.Property(s => s.StripePriceId).HasMaxLength(StripeIdLength);

        // One subscription per tenant.
        //
        // The whole product bills the organisation, not the seat, so a second row for one tenant
        // is not a second plan — it is two answers to "what is this account entitled to", and
        // whichever the query happened to read first would win. The row is created lazily on the
        // first checkout attempt, which is exactly the moment a double-clicked button could
        // insert two; this index is what makes that a database error instead of a fork.
        //
        // Also unique because SentinelDbContext.ApplyTenantIsolation adds a plain index on
        // TenantId to every ITenantOwned entity. EF resolves both calls to the same index, and
        // that one does not clear uniqueness — but it is declared here so the constraint is
        // visible in the configuration that owns this table rather than inferred from a
        // reflection loop somewhere else.
        builder.HasIndex(s => s.TenantId).IsUnique();

        // The webhook's lookup key (IBillingSubscriptionStore) and the only path Stripe has to a
        // tenant. Unique with a filter, because most rows legitimately have none: a tenant that
        // has never opened the billing screen has no Stripe customer, and without the filter
        // every one of those NULLs would collide on SQL Server, which treats NULLs as equal for
        // uniqueness. Uniqueness matters here for the same reason as above — two tenants sharing
        // a Stripe customer id would mean a payment provisioning an account that did not make it.
        builder.HasIndex(s => s.StripeCustomerId)
            .IsUnique()
            .HasFilter("[StripeCustomerId] IS NOT NULL");

        // Not unique, and not filtered: this one is for lookups and for a human joining a Stripe
        // dashboard row to an account during a support ticket.
        builder.HasIndex(s => s.StripeSubscriptionId);

        // Cascade, matching how every other tenant-owned table is deleted. TenantPurgeService
        // removes subscriptions explicitly anyway — it never relies on cascades — but the
        // constraint should say what is true rather than leaving a Restrict that only the purge
        // service's ordering happens to satisfy.
        builder.HasOne(s => s.Tenant)
            .WithOne(t => t.Subscription)
            .HasForeignKey<Subscription>(s => s.TenantId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

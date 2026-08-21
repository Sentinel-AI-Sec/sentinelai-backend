using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

public class ScanQuotaCounterConfiguration : IEntityTypeConfiguration<ScanQuotaCounter>
{
    public void Configure(EntityTypeBuilder<ScanQuotaCounter> builder)
    {
        // Unique, and that is what makes the counter correct rather than merely indexed. Two
        // first-submissions of the day race to insert; without this both succeed and the tenant
        // gets two counters, each under the limit, and therefore twice the allowance. With it the
        // loser gets a DbUpdateException that ScanQuotaCounterStore treats as "the row exists now"
        // and retries the conditional update against.
        builder.HasIndex(c => new { c.TenantId, c.UtcDay }).IsUnique();

        builder.HasOne(c => c.Tenant)
            .WithMany()
            .HasForeignKey(c => c.TenantId)
            // Counters are the tenant's own usage record and mean nothing without it. Cascade so
            // account deletion does not have to remember them -- see TenantPurgeService, which
            // deletes explicitly for the entities that need ordering.
            .OnDelete(DeleteBehavior.Cascade);
    }
}

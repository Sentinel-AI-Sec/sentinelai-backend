using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

public class ScanAuditIntegrityConfiguration : IEntityTypeConfiguration<ScanAuditIntegrity>
{
    public void Configure(EntityTypeBuilder<ScanAuditIntegrity> builder)
    {
        // One row per scan. A second would mean a scan was audited twice, which the pipeline has
        // no path to -- and if one ever appears, a unique violation is a far better way to find out
        // than two rows quietly disagreeing about what happened.
        builder.HasIndex(a => a.ScanJobId).IsUnique();

        builder.HasOne(a => a.ScanJob)
            .WithOne()
            .HasForeignKey<ScanAuditIntegrity>(a => a.ScanJobId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

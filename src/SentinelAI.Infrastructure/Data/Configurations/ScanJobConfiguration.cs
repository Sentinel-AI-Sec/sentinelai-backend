using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

public class ScanJobConfiguration : IEntityTypeConfiguration<ScanJob>
{
    public void Configure(EntityTypeBuilder<ScanJob> builder)
    {
        // Stored by name, like every other enum here, so the column is readable in a query
        // window and the enum's ordinals stay free to change.
        builder.Property(s => s.Status)
            .HasConversion<string>();

        builder.Property(s => s.Stage)
            .HasConversion<string>();

        // What makes GET /v1/scans a keyset seek rather than a sort of every scan the tenant has
        // ever run: the columns the list's WHERE and ORDER BY read, in that order.
        // ApplyTenantIsolation already adds a bare TenantId index; this is the ordered composite.
        builder.HasIndex(s => new { s.TenantId, s.StartedAt, s.Id });

        builder.HasOne(s => s.ScanBundle)
            .WithOne(b => b.ScanJob)
            .HasForeignKey<ScanBundle>(b => b.ScanJobId);

        builder.HasOne(s => s.Report)
            .WithOne(r => r.ScanJob)
            .HasForeignKey<Report>(r => r.ScanJobId);
    }
}

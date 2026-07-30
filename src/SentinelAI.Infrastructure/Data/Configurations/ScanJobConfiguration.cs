using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

public class ScanJobConfiguration : IEntityTypeConfiguration<ScanJob>
{
    public void Configure(EntityTypeBuilder<ScanJob> builder)
    {
        builder.HasOne(s => s.ScanBundle)
            .WithOne(b => b.ScanJob)
            .HasForeignKey<ScanBundle>(b => b.ScanJobId);

        builder.HasOne(s => s.Report)
            .WithOne(r => r.ScanJob)
            .HasForeignKey<Report>(r => r.ScanJobId);
    }
}

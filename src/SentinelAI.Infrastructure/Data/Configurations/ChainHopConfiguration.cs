using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

public class ChainHopConfiguration : IEntityTypeConfiguration<ChainHop>
{
    public void Configure(EntityTypeBuilder<ChainHop> builder)
    {
        builder.HasOne(ch => ch.Finding)
            .WithMany(f => f.ChainHops)
            .HasForeignKey(ch => ch.FindingId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(ch => ch.Chain)
            .WithMany(c => c.ChainHops)
            .HasForeignKey(ch => ch.ChainId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(ch => ch.Edge)
            .WithMany(e => e.ChainHops)
            .HasForeignKey(ch => ch.EdgeId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}

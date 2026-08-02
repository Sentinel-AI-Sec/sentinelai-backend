using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

public class ChainConfiguration : IEntityTypeConfiguration<Chain>
{
    public void Configure(EntityTypeBuilder<Chain> builder)
    {
        builder.Property(c => c.Status)
            .HasConversion<string>();

        // Stored by name, like every other enum here, so the column is readable in a query
        // window and the enum's ordinals stay free to change.
        builder.Property(c => c.MinConfidence)
            .HasConversion<string>();
    }
}

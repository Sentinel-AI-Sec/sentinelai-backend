using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

public class GraphNodeConfiguration : IEntityTypeConfiguration<GraphNode>
{
    public void Configure(EntityTypeBuilder<GraphNode> builder)
    {
        builder.HasIndex(g => new { g.ScanJobId, g.NodeKey })
            .IsUnique();

        builder.Property(g => g.NodeType)
            .HasConversion<string>();

        builder.Property(g => g.Layer)
            .HasConversion<string>();
    }
}

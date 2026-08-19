using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

public class FindingConfiguration : IEntityTypeConfiguration<Finding>
{
    public void Configure(EntityTypeBuilder<Finding> builder)
    {
        builder.Property(f => f.Layer)
            .HasConversion<string>();

        // In-pipeline only (SEC-15): the rule id travels from the extractor to the rule-mapping
        // lookup and is spent there. The findings table has no check_id column by design — the
        // resolved cwe_id is the durable result, the tool's rule id is not.
        builder.Ignore(f => f.CheckId);

        // Same treatment, same reason (SEC-16): the tool-reported location travels from the
        // extractor to the unify step, which spends it building node_ref. The findings table
        // has no location column — node_ref is the durable result, and it is the one the graph
        // joins on.
        builder.Ignore(f => f.Location);
    }
}

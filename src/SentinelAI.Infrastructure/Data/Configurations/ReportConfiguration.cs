using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

/// <summary>
/// Storage shape for the report, including SEC-31's per-tier cost columns.
/// </summary>
public class ReportConfiguration : IEntityTypeConfiguration<Report>
{
    /// <summary>
    /// Six decimal places, not SQL Server's default two.
    /// </summary>
    /// <remarks>
    /// A whole debate is a handful of calls of a few thousand tokens, so at list prices it
    /// costs cents. At <c>decimal(18,2)</c> every one of those rounds to 0.00 and the metric
    /// this task exists to produce reads as free — the numbers would be stored, and stored
    /// wrong, which is worse than not storing them. Six places keeps a sub-cent scan legible
    /// and still totals thousands of scans without loss.
    /// </remarks>
    private const int CostScale = 6;

    public void Configure(EntityTypeBuilder<Report> builder)
    {
        builder.Property(r => r.CostCurrency).HasMaxLength(3);

        builder.Property(r => r.HighTierCost).HasPrecision(18, CostScale);
        builder.Property(r => r.CheapTierCost).HasPrecision(18, CostScale);

        // Computed from the two columns above, so it is a read-side convenience and not a
        // third copy of the same fact that could disagree with them.
        builder.Ignore(r => r.TotalCost);
    }
}

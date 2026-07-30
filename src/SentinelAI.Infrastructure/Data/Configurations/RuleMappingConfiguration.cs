using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

public class RuleMappingConfiguration : IEntityTypeConfiguration<RuleMapping>
{
    public void Configure(EntityTypeBuilder<RuleMapping> builder)
    {
        builder.HasIndex(r => new { r.SourceTool, r.CheckId })
            .IsUnique();

        builder.HasData(
            new RuleMapping
            {
                Id = Guid.Parse("f099c288-0f0c-43f1-b956-f6a6233ba3eb"),
                SourceTool = "roslyn",
                CheckId = "SCS0028",
                CweId = "CWE-502",
                Notes = "Baseline exact lookup map"
            },
            new RuleMapping
            {
                Id = Guid.Parse("b882650b-47e1-4c07-ba96-7fc3b8a13a21"),
                SourceTool = "checkov",
                CheckId = "CKV_AWS_20",
                CweId = "CWE-284",
                Notes = "Baseline exact lookup map"
            }
        );
    }
}

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

public class ChainHopConfiguration : IEntityTypeConfiguration<ChainHop>
{
    public void Configure(EntityTypeBuilder<ChainHop> builder)
    {
        // Stored by name like every other enum here, so the column is readable in a query window
        // and so "unassessed" and "unattributed" are legible as the two different kinds of
        // silence they are, rather than as 0 and 1 (audit 42-A).
        builder.Property(ch => ch.BlueVerdict)
            .HasConversion<string>();

        // BlueValidated is derived from BlueVerdict and has no backing field, so EF must be told
        // not to look for a column for it. It used to be one; the migration drops it. Keeping
        // both would let a row claim "validated" while its verdict said "refuted", which is the
        // exact class of disagreement audit 42-A was about.
        builder.Ignore(ch => ch.BlueValidated);

        // Optional, like the edge below it: see ChainHop.FindingId's own remarks for why a hop
        // may legitimately have no finding.
        builder.HasOne(ch => ch.Finding)
            .WithMany(f => f.ChainHops)
            .HasForeignKey(ch => ch.FindingId)
            .IsRequired(false)
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

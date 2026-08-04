using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        // One account per email, globally — not per-tenant. A user belongs to exactly one
        // tenant today (User.TenantId is a single FK), so "the same email in two tenants"
        // isn't a supported shape yet; that's invite-flow territory, not this pass.
        builder.HasIndex(u => u.Email).IsUnique();
    }
}

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

/// <summary>
/// Storage shape for a project, and the uniqueness that makes its id stable.
/// </summary>
public class ProjectConfiguration : IEntityTypeConfiguration<Project>
{
    /// <summary>
    /// Mirrors <c>CreateProjectCommandValidator.MaxRepoUrlLength</c>. The column is bounded rather
    /// than <c>nvarchar(max)</c> because the unique index below cannot be built over an unbounded
    /// one; the validator refuses anything longer so a URL is never silently truncated into a
    /// different URL than the caller sent.
    /// </summary>
    private const int RepoUrlLength = 500;

    private const int BranchLength = 255;

    private const int InstallationIdLength = 100;

    public void Configure(EntityTypeBuilder<Project> builder)
    {
        builder.Property(p => p.RepoUrl).HasMaxLength(RepoUrlLength).IsRequired();
        builder.Property(p => p.DefaultBranch).HasMaxLength(BranchLength).IsRequired();
        builder.Property(p => p.GithubInstallationId).HasMaxLength(InstallationIdLength);

        // One project per repository per tenant.
        //
        // The GitHub Action is configured with a literal project id in a workflow file, so the id
        // has to keep meaning the same repository for as long as that workflow runs. Without this
        // index, a provisioning script run twice — or two admins registering the same repo —
        // produces two projects for one repository, and scans then arrive split across both with
        // nothing reporting that anything went wrong. CreateProjectCommandHandler checks for the
        // duplicate before inserting so the caller gets a 409 with the existing id rather than a
        // database error; this index is what makes that check a guarantee instead of a race.
        //
        // Scoped to the tenant, not global: two customers scanning the same public repository is
        // ordinary, and a global constraint would let the first one to register it silently deny
        // the second.
        builder.HasIndex(p => new { p.TenantId, p.RepoUrl }).IsUnique();
    }
}

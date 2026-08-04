using SentinelAI.Domain.Abstractions;

namespace SentinelAI.Domain.Models
{
    public class Project : ITenantOwned
    {
        public Guid Id { get; set; }
        public Guid TenantId { get; set; }
        public string RepoUrl { get; set; } = string.Empty;
        public string DefaultBranch { get; set; } = string.Empty;
        public string? GithubInstallationId { get; set; }

        public Tenant? Tenant { get; set; }
        public ICollection<ScanJob> ScanJobs { get; set; } = new List<ScanJob>();
    }
}

using SentinelAI.Domain.Abstractions;

namespace SentinelAI.Domain.Models
{
    public class User : ITenantOwned
    {
        public Guid Id { get; set; }
        public Guid TenantId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;

        /// <summary>Not enforced anywhere yet — there is no email-sending pipeline in this
        /// app. Exists now so enabling verification later is a one-line check, not a
        /// migration (SEC: auth v1).</summary>
        public bool IsEmailVerified { get; set; }

        public DateTime CreatedAt { get; set; }

        public Tenant? Tenant { get; set; }
        public ICollection<ScanJob> TriggeredJobs { get; set; } = new List<ScanJob>();
    }
}

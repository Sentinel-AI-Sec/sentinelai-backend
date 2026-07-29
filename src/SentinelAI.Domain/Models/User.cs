namespace SentinelAI.Domain.Models
{
    public class User
    {
        public Guid Id { get; set; }
        public Guid TenantId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }

        public Tenant? Tenant { get; set; }
        public ICollection<ScanJob> TriggeredJobs { get; set; } = new List<ScanJob>();
    }
}

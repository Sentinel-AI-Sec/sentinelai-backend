namespace SentinelAI.Domain.Models
{
    public class Report
    {
        public Guid Id { get; set; }
        public Guid ScanJobId { get; set; }
        public string Summary { get; set; } = string.Empty;
        public string Framing { get; set; } = string.Empty;
        public bool Retained { get; set; }
        public string? FeedbackSlot { get; set; }
        public DateTime CreatedAt { get; set; }

        public ScanJob? ScanJob { get; set; }
        public ICollection<Citation> Citations { get; set; } = new List<Citation>();
    }
}

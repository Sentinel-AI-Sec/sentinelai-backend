namespace SentinelAI.Domain.Models
{
    public class Chain
    {
        public Guid Id { get; set; }
        public Guid ScanJobId { get; set; }
        public int HopCount { get; set; }
        public int Priority { get; set; }
        public string Status { get; set; } = string.Empty;
        public string MinConfidence { get; set; } = string.Empty;

        public ScanJob? ScanJob { get; set; }
        public ICollection<ChainHop> ChainHops { get; set; } = new List<ChainHop>();
    }
}

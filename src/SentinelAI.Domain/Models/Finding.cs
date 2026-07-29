namespace SentinelAI.Domain.Models
{
    public class Finding
    {
        public Guid Id { get; set; }
        public Guid ScanJobId { get; set; }
        public string SourceTool { get; set; } = string.Empty;
        public string Layer { get; set; } = string.Empty;
        public int Severity { get; set; }
        public string? CweId { get; set; }
        public string? CveId { get; set; }
        public string NodeRef { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public bool Redacted { get; set; }

        public ScanJob? ScanJob { get; set; }
        public ICollection<ChainHop> ChainHops { get; set; } = new List<ChainHop>();
    }
}

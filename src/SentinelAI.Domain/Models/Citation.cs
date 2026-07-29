namespace SentinelAI.Domain.Models
{
    public class Citation
    {
        public Guid Id { get; set; }
        public Guid? ChainHopId { get; set; }
        public Guid? ReportId { get; set; }
        public string KnowledgeId { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Collection { get; set; } = string.Empty;

        public ChainHop? ChainHop { get; set; }
        public Report? Report { get; set; }
    }
}

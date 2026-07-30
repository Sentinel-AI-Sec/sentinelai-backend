namespace SentinelAI.Domain.Models
{
    public class RuleMapping
    {
        public Guid Id { get; set; }
        public string SourceTool { get; set; } = string.Empty;
        public string CheckId { get; set; } = string.Empty;
        public string? CweId { get; set; }
        public string? CveId { get; set; }
        public string? Notes { get; set; }
    }
}
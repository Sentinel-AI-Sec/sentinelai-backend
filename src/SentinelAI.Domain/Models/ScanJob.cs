using SentinelAI.Domain.Enums;

namespace SentinelAI.Domain.Models
{
    public class ScanJob
    {
        public Guid Id { get; set; }
        public Guid ProjectId { get; set; }
        public Guid? TriggeredBy { get; set; }
        public string PrRef { get; set; } = string.Empty;
        public string CommitSha { get; set; } = string.Empty;
        public ScanStatus Status { get; set; }
        public string CorpusVersion { get; set; } = string.Empty;
        public bool BundlePurged { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime? CompletedAt { get; set; }

        public Project? Project { get; set; }
        public User? TriggeringUser { get; set; }
        public ScanBundle? ScanBundle { get; set; }
        public Report? Report { get; set; }
        public ScanStage Stage { get; set; }          // ScanStage.*
        public string ModelTierHint { get; set; } = "auto";        // auto | economy | premium
        public bool RetainReport { get; set; }                     // metadata.retain_report
        public string? FailureReason { get; set; }   

        public ICollection<Finding> Findings { get; set; } = new List<Finding>();
        public ICollection<GraphNode> GraphNodes { get; set; } = new List<GraphNode>();
        public ICollection<GraphEdge> GraphEdges { get; set; } = new List<GraphEdge>();
        public ICollection<Chain> Chains { get; set; } = new List<Chain>();
    }
}

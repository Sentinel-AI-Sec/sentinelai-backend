using SentinelAI.Domain.Enums;

namespace SentinelAI.Domain.Models
{
    public class GraphEdge
    {
        public Guid Id { get; set; }
        public Guid ScanJobId { get; set; }
        public Guid FromNodeId { get; set; }
        public Guid ToNodeId { get; set; }
        public string Relation { get; set; } = string.Empty;
        public Seam Seam { get; set; }
        public Confidence Confidence { get; set; }
        public bool OrientedAttackDir { get; set; }

        public ScanJob? ScanJob { get; set; }
        public GraphNode? FromNode { get; set; }
        public GraphNode? ToNode { get; set; }
        public ICollection<ChainHop> ChainHops { get; set; } = new List<ChainHop>();
    }
}

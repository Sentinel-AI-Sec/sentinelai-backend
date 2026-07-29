namespace SentinelAI.Domain.Models
{
    public class GraphEdge
    {
        public Guid Id { get; set; }
        public Guid ScanJobId { get; set; }
        public Guid FromNodeId { get; set; }
        public Guid ToNodeId { get; set; }
        public string Relation { get; set; } = string.Empty;
        public string Seam { get; set; } = string.Empty;
        public string Confidence { get; set; } = string.Empty;
        public bool OrientedAttackDir { get; set; }

        public ScanJob? ScanJob { get; set; }
        public GraphNode? FromNode { get; set; }
        public GraphNode? ToNode { get; set; }
        public ICollection<ChainHop> ChainHops { get; set; } = new List<ChainHop>();
    }
}

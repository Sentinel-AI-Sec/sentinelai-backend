namespace SentinelAI.Domain.Models
{
    public class GraphNode
    {
        public Guid Id { get; set; }
        public Guid ScanJobId { get; set; }
        public string NodeKey { get; set; } = string.Empty;
        public string NodeType { get; set; } = string.Empty;
        public string Layer { get; set; } = string.Empty;
        public bool IsHot { get; set; }
        public string? Attrs { get; set; }

        public ScanJob? ScanJob { get; set; }
        public ICollection<GraphEdge> OutgoingEdges { get; set; } = new List<GraphEdge>();
        public ICollection<GraphEdge> IncomingEdges { get; set; } = new List<GraphEdge>();
    }
}

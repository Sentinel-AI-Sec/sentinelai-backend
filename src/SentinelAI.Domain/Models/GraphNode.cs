using SentinelAI.Domain.Enums;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Domain.Models
{
    public class GraphNode
    {
        /// <summary>
        /// Builds a node with <see cref="NodeKey"/> and <see cref="NodeType"/> guaranteed to
        /// agree. Every extractor should come through here.
        /// </summary>
        /// <remarks>
        /// Setting the two independently is how the same resource ends up under two keys —
        /// the island bug SEC-03 exists to prevent. The setters stay public because EF Core
        /// materializes through them, so this is the blessed path rather than the only one.
        /// </remarks>
        public static GraphNode Create(
            Guid scanJobId, NodeType nodeType, string identifier, Layer layer, bool isHot = false) =>
            new()
            {
                ScanJobId = scanJobId,
                NodeKey = NodeId.For(nodeType, identifier),
                NodeType = nodeType,
                Layer = layer,
                IsHot = isHot,
            };

        public Guid Id { get; set; }
        public Guid ScanJobId { get; set; }
        public string NodeKey { get; set; } = string.Empty;
        public NodeType NodeType { get; set; }
        public Layer Layer { get; set; }
        public bool IsHot { get; set; }
        public string? Attrs { get; set; }

        public ScanJob? ScanJob { get; set; }
        public ICollection<GraphEdge> OutgoingEdges { get; set; } = new List<GraphEdge>();
        public ICollection<GraphEdge> IncomingEdges { get; set; } = new List<GraphEdge>();
    }
}

using SentinelAI.Domain.Abstractions;

namespace SentinelAI.Domain.Models
{
    public class ChainHop : ITenantOwned
    {
        public Guid Id { get; set; }
        public Guid TenantId { get; set; }
        public Guid ChainId { get; set; }

        /// <summary>
        /// The finding decorating this hop's node, if one does.
        /// </summary>
        /// <remarks>
        /// Nullable, which is a deliberate widening of the D2 schema (SEC-20). A hop is a place
        /// on a real edge, and plenty of such places carry no scanner finding — a container
        /// image, a task definition, an IAM role nobody wrote a rule about. Requiring a finding
        /// would mean either dropping those hops, which breaks the chain, or inventing one,
        /// which fabricates a result. <c>edge_id</c> is nullable for the mirror-image reason:
        /// the seed hop arrived from nowhere.
        /// </remarks>
        public Guid? FindingId { get; set; }
        public Guid? EdgeId { get; set; }
        public int HopOrder { get; set; }
        public string TechniqueId { get; set; } = string.Empty;
        public bool BlueValidated { get; set; }

        public Chain? Chain { get; set; }
        public Finding? Finding { get; set; }
        public GraphEdge? Edge { get; set; }
        public ICollection<Citation> Citations { get; set; } = new List<Citation>();
    }
}

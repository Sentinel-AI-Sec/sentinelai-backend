using SentinelAI.Domain.Abstractions;

namespace SentinelAI.Domain.Models
{
    public class ChainHop : ITenantOwned
    {
        public Guid Id { get; set; }
        public Guid TenantId { get; set; }
        public Guid ChainId { get; set; }
        public Guid FindingId { get; set; }
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

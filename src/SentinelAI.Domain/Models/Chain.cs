using SentinelAI.Domain.Enums;

namespace SentinelAI.Domain.Models
{
    public class Chain
    {
        public Guid Id { get; set; }
        public Guid ScanJobId { get; set; }
        public int HopCount { get; set; }
        public int Priority { get; set; }
        public ChainStatus Status { get; set; }

        /// <summary>
        /// The weakest join anywhere in the chain (AID-01 section 3.3). Build it with
        /// <see cref="ConfidenceExtensions.Weakest{T}"/> over the chain's edges rather than
        /// assigning it directly — a chain that claims more confidence than one of its hops
        /// is the false-positive this field exists to prevent.
        /// </summary>
        public Confidence MinConfidence { get; set; } = Confidence.Certain;

        public ScanJob? ScanJob { get; set; }
        public ICollection<ChainHop> ChainHops { get; set; } = new List<ChainHop>();
    }
}

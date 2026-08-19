using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;

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

        /// <summary>
        /// The ATT&amp;CK technique Red named for this hop — <c>T1078</c>, <c>T1078.004</c> —
        /// or empty when it named none this scan's own brief could ground.
        /// </summary>
        /// <remarks>
        /// Empty is the normal case and is not a defect: Red is asked for an id only when the
        /// knowledge it was given names one, and an id it recalled from nowhere is exactly the
        /// value <c>HopVerdictReader</c> refuses to persist. A renderer must therefore treat
        /// empty as "no technique", not as a link to
        /// <c>https://attack.mitre.org/techniques/</c> with nothing after the slash (audit 42-A).
        /// </remarks>
        public string TechniqueId { get; set; } = string.Empty;

        /// <summary>
        /// What Blue's validation turn said about this hop, including the two ways it can have
        /// said nothing usable. See <see cref="HopVerdict"/> for why this is not a bool.
        /// </summary>
        public HopVerdict BlueVerdict { get; set; } = HopVerdict.Unassessed;

        /// <summary>
        /// The narrow question "did Blue confirm this hop?", derived rather than stored.
        /// </summary>
        /// <remarks>
        /// It was a column until audit 42-A, and a column nothing ever wrote. Deriving it from
        /// <see cref="BlueVerdict"/> means the two can no longer disagree, and means every
        /// non-confirmation — refuted, unresolved, unattributed, never assessed — answers this
        /// question with the same honest <c>false</c> while staying separable in
        /// <see cref="BlueVerdict"/> for anyone who needs to know <em>which</em>. Mapped out in
        /// <c>ChainHopConfiguration</c>.
        /// </remarks>
        public bool BlueValidated => BlueVerdict == HopVerdict.Confirmed;

        public Chain? Chain { get; set; }
        public Finding? Finding { get; set; }
        public GraphEdge? Edge { get; set; }
        public ICollection<Citation> Citations { get; set; } = new List<Citation>();
    }
}

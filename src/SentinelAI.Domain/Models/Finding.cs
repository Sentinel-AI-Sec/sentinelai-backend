using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;

namespace SentinelAI.Domain.Models
{
    public class Finding : ITenantOwned
    {
        public Guid Id { get; set; }
        public Guid TenantId { get; set; }
        public Guid ScanJobId { get; set; }
        public string SourceTool { get; set; } = string.Empty;
        public Layer Layer { get; set; }
        public int Severity { get; set; }
        public string? CweId { get; set; }
        public string? CveId { get; set; }

        /// <summary>
        /// The reporting tool's own rule identifier — <c>SCS0028</c>, <c>CKV_AWS_20</c>,
        /// <c>AVD-AWS-0089</c>. Carried from the extractor to the rule-mapping step (SEC-15),
        /// which uses (<see cref="SourceTool"/>, <see cref="CheckId"/>) as the exact lookup key
        /// for a missing <see cref="CweId"/>.
        /// </summary>
        /// <remarks>
        /// Deliberately <em>not</em> a column: the <c>findings</c> table in the D2 database
        /// design has no <c>check_id</c>, and the canonical Finding contract is fixed (SEC-03).
        /// <c>FindingConfiguration</c> maps this property out, so it lives only for the length
        /// of the normalization run and never widens the persisted shape.
        /// </remarks>
        public string? CheckId { get; set; }

        /// <summary>
        /// Where the tool says the problem is, normalized: a repo-relative <c>path</c> or
        /// <c>path:line</c> for code and infrastructure, the package coordinate
        /// <c>name@version</c> for dependencies. Null when the tool reported no location.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Carried from the extractor to the unify step (SEC-16), which uses it twice: to tell
        /// two findings apart when deduplicating, and as the subject the
        /// <see cref="NodeRef"/> is built from.
        /// </para>
        /// <para>
        /// Normalized on the way in, and that is load-bearing: Roslyn and OSV-Scanner emit the
        /// build agent's absolute author path, which would make the same finding scanned on two
        /// machines dedup as two findings on two nodes, silently.
        /// </para>
        /// <para>
        /// Not a column, for the same reason as <see cref="CheckId"/>: the D2 <c>findings</c>
        /// table is fixed and has no location. It is spent at the unify step — the durable
        /// result is <see cref="NodeRef"/>, which <em>is</em> in the contract.
        /// </para>
        /// </remarks>
        public string? Location { get; set; }

        public string NodeRef { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public bool Redacted { get; set; }

        public ScanJob? ScanJob { get; set; }
        public ICollection<ChainHop> ChainHops { get; set; } = new List<ChainHop>();
    }
}

using SentinelAI.Domain.Abstractions;

namespace SentinelAI.Domain.Models
{
    /// <summary>
    /// How many scans one tenant has submitted on one UTC day.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One row per tenant per day, created on that day's first submission. Counting rows in
    /// <c>ScanJobs</c> instead would look simpler and be wrong twice over: a purged or deleted scan
    /// would hand back quota that was already spent, and the count would have to scan a growing
    /// table on the hot path of every submission.
    /// </para>
    /// <para>
    /// The day is stored as a <see cref="DateOnly"/> and not derived from a timestamp range, so the
    /// unique index on (tenant, day) is what enforces one counter per day — the reset is a new row
    /// appearing, not a job that has to run at midnight.
    /// </para>
    /// <para>
    /// <see cref="ITenantOwned"/>, so it inherits the query filter and cannot be read across
    /// tenants by a query that forgot to say so.
    /// </para>
    /// </remarks>
    public class ScanQuotaCounter : ITenantOwned
    {
        public Guid Id { get; set; }

        public Guid TenantId { get; set; }

        /// <summary>The UTC day this counter is for.</summary>
        public DateOnly UtcDay { get; set; }

        /// <summary>Scans submitted on <see cref="UtcDay"/>.</summary>
        public int Count { get; set; }

        public Tenant? Tenant { get; set; }
    }
}

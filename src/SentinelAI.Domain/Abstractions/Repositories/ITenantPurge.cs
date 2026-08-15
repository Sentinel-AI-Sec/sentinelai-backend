namespace SentinelAI.Domain.Abstractions.Repositories;

/// <summary>How many rows of each kind an account deletion removed.</summary>
/// <remarks>
/// Counted and returned rather than discarded so the deletion is auditable: "we deleted your
/// data" is a claim someone may later have to substantiate, and a caller that gets no numbers
/// back can only report that nothing threw.
/// </remarks>
/// <param name="Rows">Entity name → rows deleted. Zero-count entities are included.</param>
/// <param name="BundlesPurged">Scan bundles removed from storage, not just from the database.</param>
public sealed record TenantPurgeReport(IReadOnlyDictionary<string, int> Rows, int BundlesPurged)
{
    /// <summary>Total rows removed across every table.</summary>
    public int TotalRows => Rows.Values.Sum();
}

/// <summary>
/// Permanently removes everything belonging to one tenant (SEC-35).
/// </summary>
/// <remarks>
/// <para>
/// Deletion is irreversible by design: purge means the data is gone, not hidden behind a flag.
/// A soft-delete would leave us still holding what we promised to destroy, which is the failure
/// this exists to prevent.
/// </para>
/// <para>
/// It lives behind an interface because the ordering it has to respect is a property of the
/// relational schema — see the implementation — and a caller in the Application layer should be
/// asking for "delete this account", not sequencing eleven tables.
/// </para>
/// </remarks>
public interface ITenantPurge
{
    Task<TenantPurgeReport> PurgeAsync(Guid tenantId, CancellationToken ct = default);
}

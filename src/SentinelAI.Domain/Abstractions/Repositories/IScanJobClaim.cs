namespace SentinelAI.Domain.Abstractions.Repositories;

/// <summary>
/// Takes ownership of exactly one queued scan job, atomically (SEC-46).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is a port and not a LINQ query.</b> The only correct way to hand a job to one
/// worker and no other is a single statement that tests and sets the status together. A
/// <c>SELECT</c> for a queued job followed by an <c>UPDATE</c> marking it running is two
/// statements, and between them a second worker — or the same worker's next polling tick —
/// reads the same row and starts a duplicate run. Duplicate runs here are not merely wasteful:
/// the debate stage makes billable model calls, and both runs write findings, graph and chain
/// rows for the same job id.
/// </para>
/// <para>
/// The statement itself is provider-specific, which is the other reason this is an interface.
/// It is expressed in Infrastructure against SQL Server; Application and the worker depend on
/// the guarantee, not on the dialect.
/// </para>
/// <para>
/// <b>It deliberately does not return a <see cref="Models.ScanJob"/>.</b> Every tenant-owned
/// entity is behind the tenant query filter, which resolves from <see cref="ICallerContext"/>
/// when the <c>DbContext</c> is constructed — and a background worker has no caller until this
/// method tells it whose job it just claimed. So the claim returns the two facts needed to
/// establish that identity, and the job is read normally afterwards, through a context that
/// knows which tenant it belongs to.
/// </para>
/// </remarks>
public interface IScanJobClaim
{
    /// <summary>
    /// Moves one <c>Queued</c> job to <c>Running</c> and returns it, or null when none is waiting.
    /// </summary>
    /// <returns>
    /// The claimed job's identity, or null. Null is the ordinary case — an idle queue — and not
    /// an error.
    /// </returns>
    Task<ClaimedScanJob?> ClaimNextAsync(CancellationToken ct = default);
}

/// <summary>
/// The identity of a job this worker now owns.
/// </summary>
/// <param name="ScanJobId">The claimed job.</param>
/// <param name="TenantId">
/// Its tenant, carried out of the claim because nothing else can supply it. It is read from the
/// row by the same statement that claimed it, so it cannot disagree with the job the worker is
/// about to run.
/// </param>
public sealed record ClaimedScanJob(Guid ScanJobId, Guid TenantId);

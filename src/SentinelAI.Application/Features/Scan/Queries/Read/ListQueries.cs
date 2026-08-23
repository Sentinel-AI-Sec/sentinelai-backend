using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Queries.Read;

// The enumeration half of the read API.
//
// SEC-40 delivered reads addressed by id and nothing that enumerates them, and both repositories
// wrote the consequence down rather than papering over it: ScanController's read block says the
// screen is built against per-id reads, and the console's recents.ts says in as many words that
// "the read API deliberately has no 'list my scans' or 'list my reports' endpoint … that is a
// real gap in the API". The gap forced the dashboard to substitute a browser-local index of the
// ids this browser happened to open, which is not the tenant's history — it is one machine's
// memory of it, lost on a cache clear and invisible to a colleague.
//
// These three close it. They enumerate *within one tenant* and nothing else: like every other
// read, the only scoping input is the tenant on the verified token, so there is no parameter a
// caller could set to widen the result past their own data.

/// <summary>
/// A page of the tenant's scan jobs, newest first.
/// </summary>
/// <remarks>
/// Newest first rather than oldest first — the opposite of <see cref="GetFindingsQuery"/> and
/// <see cref="GetChainsQuery"/>, and deliberately. Those page through the contents of one scan,
/// where the natural reading order is the order the rows were written. This pages through history,
/// where the first page a person wants is the most recent one; oldest-first would put a tenant's
/// very first scan at the top of the console forever.
/// </remarks>
/// <param name="ProjectId">Optional: only scans of this project. A project belonging to another
/// tenant matches nothing rather than erroring — it is simply not one of this tenant's projects.</param>
/// <param name="Status">Optional: <c>queued</c>, <c>running</c>, <c>completed</c> or <c>failed</c>.</param>
/// <param name="Stage">Optional: <c>received</c>, <c>normalize</c>, <c>graph</c>, <c>retrieve</c>,
/// <c>debate</c> or <c>report</c>.</param>
public sealed record ListScansQuery(
    string? Cursor = null,
    int? Limit = null,
    Guid? ProjectId = null,
    string? Status = null,
    string? Stage = null) : IRequest<Response>;

/// <summary>
/// A page of the tenant's draft audits, newest first.
/// </summary>
/// <remarks>
/// A report exists only where the submitter opted into retention (SEC-35), so this list is
/// <em>not</em> a list of scans that produced an audit — it is a list of the audits still held.
/// A scan that ran, was reported on and was then purged as asked is correctly absent, which is
/// why the scan list carries <c>report_id</c> and this one cannot be derived from it.
/// </remarks>
/// <param name="ProjectId">Optional: only reports on scans of this project.</param>
public sealed record ListReportsQuery(
    string? Cursor = null,
    int? Limit = null,
    Guid? ProjectId = null) : IRequest<Response>;

/// <summary>
/// Counts over one scan: findings by layer and severity, the graph's size, chains by status.
/// </summary>
/// <remarks>
/// <para>
/// This exists because of a specific honesty problem the console documented and could not solve
/// on its own. <c>GET /v1/scans/{id}/findings</c> is cursor-paged and returns no total, so the
/// findings screen "counts the rows it has loaded, not the scan, because under a cursor it cannot
/// honestly claim the latter". A page count is the wrong number to put next to a filter — it
/// answers "how many have I fetched", and every reader will parse it as "how many are there".
/// </para>
/// <para>
/// The counts are computed by the database, over the same tenant-scoped predicates the paged
/// queries use, so a total here and a walk of every page agree by construction. Severity is
/// reported as the 0–4 buckets the rows actually carry rather than as an average: severities are
/// ordinal, and the mean of a 4 and two 0s is not a description of anything.
/// </para>
/// </remarks>
public sealed record GetScanSummaryQuery(Guid ScanJobId) : IRequest<Response>;

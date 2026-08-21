using System.Linq.Expressions;
using System.Net;
using MediatR;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Application.Common.Paging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Queries.Read;

// ---- GET /v1/scans ---------------------------------------------------------------------

/// <summary>
/// Pages the tenant's scan history, newest first.
/// </summary>
/// <remarks>
/// <para>
/// Every filter is optional and every one of them <em>narrows</em>. There is no parameter that
/// widens the result, and in particular there is no tenant parameter: the tenant comes from the
/// verified token, exactly as it does for the by-id reads (SEC-32). A <c>project_id</c> naming
/// another tenant's project matches no rows rather than erroring, which is the same
/// indistinguishable-from-absent answer the by-id reads give.
/// </para>
/// <para>
/// The explicit <c>TenantId</c> predicate duplicates the global query filter deliberately. SEC-32's
/// own warning is that isolation which holds only because of a filter configured somewhere else is
/// isolation nobody can verify at the call site, and a list endpoint is the highest-consequence
/// place for that to be true — a missing scope on a by-id read leaks one row, and on this one it
/// would leak the table.
/// </para>
/// </remarks>
public sealed class ListScansQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<ListScansQuery, Response>
{
    public async Task<Response> Handle(ListScansQuery request, CancellationToken ct)
    {
        var (failure, tenantId) = await ReadGuard.AuthorizeTenantAsync(caller, AuthScopes.ScanRead);
        if (failure is not null) return failure;

        var limit = Cursor.Clamp(request.Limit);

        var query = unitOfWork.Repository<ScanJob>()
            .GetTableAsNotTracked()
            .Where(j => j.TenantId == tenantId);

        if (request.ProjectId is { } projectId)
            query = query.Where(j => j.ProjectId == projectId);

        if (request.Status is { Length: > 0 })
        {
            if (!Enum.TryParse<ScanStatus>(request.Status, ignoreCase: true, out var status))
                return await Response.FailureAsync(
                    $"'{request.Status}' is not a status (queued, running, completed, failed)",
                    HttpStatusCode.BadRequest);

            query = query.Where(j => j.Status == status);
        }

        if (request.Stage is { Length: > 0 })
        {
            if (!Enum.TryParse<ScanStage>(request.Stage, ignoreCase: true, out var stage))
                return await Response.FailureAsync(
                    $"'{request.Stage}' is not a stage (received, normalize, graph, retrieve, debate, report)",
                    HttpStatusCode.BadRequest);

            query = query.Where(j => j.Stage == stage);
        }

        if (request.Cursor is { Length: > 0 })
        {
            if (!Cursor.TryDecode(request.Cursor, out var afterStarted, out var afterId))
                return await Response.FailureAsync("the cursor is not valid", HttpStatusCode.BadRequest);

            // '<', not '>', because this list runs newest first.
            //
            // Keyed on StartedAt with the id only as a tiebreak. An earlier version keyed on the
            // id alone, on the grounds that UUIDv7 is time-ordered — true of the bytes, false of
            // the sort on SQL Server, whose uniqueidentifier collation reads the trailing node
            // bytes before the leading timestamp. That made "newest first" arbitrary in
            // production while looking correct in every test, because the integration suite runs
            // on the in-memory provider. See Cursor's remarks.
            query = query.Where(j =>
                j.StartedAt < afterStarted
                || (j.StartedAt == afterStarted && j.Id.CompareTo(afterId) < 0));
        }

        var rows = await query
            .Include(j => j.Project)
            .Include(j => j.Report)
            .OrderByDescending(j => j.StartedAt)
            .ThenByDescending(j => j.Id)
            .Take(limit + 1)
            .ToListAsync(ct);

        var page = GetFindingsQueryHandler.Page(
            rows, limit, j => Cursor.Encode(j.StartedAt, j.Id), ScanListItemView.From);

        return await Response.SuccessAsync(page, "scans", HttpStatusCode.OK);
    }
}

// ---- GET /v1/reports -------------------------------------------------------------------

/// <summary>
/// Pages the tenant's retained draft audits, newest first.
/// </summary>
/// <remarks>
/// Gated on <see cref="AuthScopes.ReportRead"/> rather than <see cref="AuthScopes.ScanRead"/>, for
/// the same reason <c>GET /v1/reports/{id}</c> is: a report is the adjudicated narrative, and a
/// token allowed to poll scan status is not automatically allowed to read what the debate
/// concluded.
/// </remarks>
public sealed class ListReportsQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<ListReportsQuery, Response>
{
    public async Task<Response> Handle(ListReportsQuery request, CancellationToken ct)
    {
        var (failure, tenantId) = await ReadGuard.AuthorizeTenantAsync(caller, AuthScopes.ReportRead);
        if (failure is not null) return failure;

        var limit = Cursor.Clamp(request.Limit);

        var query = unitOfWork.Repository<Report>()
            .GetTableAsNotTracked()
            .Where(r => r.TenantId == tenantId);

        // Filtered through the report's own scan job rather than a project column on the report,
        // because a report has no project of its own — it belongs to a scan, and the scan belongs
        // to the project. Denormalizing project_id onto reports would be a second copy of that
        // fact, free to disagree with the first.
        if (request.ProjectId is { } projectId)
            query = query.Where(r => r.ScanJob != null && r.ScanJob.ProjectId == projectId);

        if (request.Cursor is { Length: > 0 })
        {
            if (!Cursor.TryDecode(request.Cursor, out var afterCreated, out var afterId))
                return await Response.FailureAsync("the cursor is not valid", HttpStatusCode.BadRequest);

            // Keyed on CreatedAt for the same reason the scan list is keyed on StartedAt.
            query = query.Where(r =>
                r.CreatedAt < afterCreated
                || (r.CreatedAt == afterCreated && r.Id.CompareTo(afterId) < 0));
        }

        var rows = await query
            .Include(r => r.ScanJob)
                .ThenInclude(j => j!.Project)
            .OrderByDescending(r => r.CreatedAt)
            .ThenByDescending(r => r.Id)
            .Take(limit + 1)
            .ToListAsync(ct);

        var page = GetFindingsQueryHandler.Page(
            rows, limit, r => Cursor.Encode(r.CreatedAt, r.Id),
            r => ReportListItemView.From(r, r.ScanJob));

        return await Response.SuccessAsync(page, "draft audits", HttpStatusCode.OK);
    }
}

// ---- GET /v1/scans/{id}/summary --------------------------------------------------------

/// <summary>
/// Counts one scan's findings, graph and chains, so a screen can state a total it can stand behind.
/// </summary>
/// <remarks>
/// <para>
/// Six aggregate queries rather than one loaded object graph. Loading the rows to count them in
/// memory would pull every finding, node, edge and chain of a scan across the wire to produce
/// about a dozen integers — on a large scan that is the most expensive read in the API, for the
/// cheapest answer.
/// </para>
/// <para>
/// The weakest join is the exception: it is computed in memory, over the distinct values only,
/// because <see cref="Confidence"/> is persisted as a string. <c>MIN</c> on that column sorts
/// alphabetically, and alphabetically <c>Certain</c> comes first — a database-side minimum would
/// confidently report the strongest join as the weakest. Reading the distinct values and taking
/// the enum minimum uses the declared ordering, where <see cref="Confidence.Unresolved"/> is 0.
/// </para>
/// </remarks>
public sealed class GetScanSummaryQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<GetScanSummaryQuery, Response>
{
    public async Task<Response> Handle(GetScanSummaryQuery request, CancellationToken ct)
    {
        var (failure, tenantId) = await ReadGuard.AuthorizeScanAsync(unitOfWork, caller, request.ScanJobId, ct);
        if (failure is not null) return failure;

        var job = await unitOfWork.ScanJobRepository.GetForTenantAsync(request.ScanJobId, tenantId, ct);
        if (job is null)
            return await Response.FailureAsync($"no scan job '{request.ScanJobId}'", HttpStatusCode.NotFound);

        var findings = unitOfWork.Repository<Finding>()
            .GetTableAsNotTracked()
            .Where(f => f.ScanJobId == request.ScanJobId);

        var byLayer = await CountByAsync(findings, f => f.Layer, ct);
        var bySeverity = await CountByAsync(findings, f => f.Severity, ct);
        var maxSeverity = await findings.MaxAsync(f => (int?)f.Severity, ct);
        var redacted = await findings.CountAsync(f => f.Redacted, ct);

        var nodes = unitOfWork.Repository<GraphNode>()
            .GetTableAsNotTracked()
            .Where(n => n.ScanJobId == request.ScanJobId);

        var nodeCount = await nodes.CountAsync(ct);
        var hotNodes = await nodes.CountAsync(n => n.IsHot, ct);

        var edges = unitOfWork.Repository<GraphEdge>()
            .GetTableAsNotTracked()
            .Where(e => e.ScanJobId == request.ScanJobId);

        var edgesByConfidence = await CountByAsync(edges, e => e.Confidence, ct);

        var chains = unitOfWork.Repository<Chain>()
            .GetTableAsNotTracked()
            .Where(c => c.ScanJobId == request.ScanJobId);

        var chainsByStatus = await CountByAsync(chains, c => c.Status, ct);

        // See the type's remarks: the enum's own ordering, not the column's.
        var chainConfidences = await chains.Select(c => c.MinConfidence).Distinct().ToListAsync(ct);

        var view = new ScanSummaryView
        {
            ScanJobId = request.ScanJobId.ToString(),
            Status = Wire.Of(job.Status),
            Stage = Wire.Of(job.Stage),
            ReportId = job.Report?.Id.ToString(),
            Findings = new FindingsSummaryView
            {
                Total = bySeverity.Values.Sum(),
                ByLayer = Buckets.Of(Enum.GetValues<Layer>(), l => Wire.Of(l), byLayer),
                BySeverity = Buckets.Severity(bySeverity),
                MaxSeverity = maxSeverity,
                Redacted = redacted,
            },
            Graph = new GraphSummaryView
            {
                Nodes = nodeCount,
                Edges = edgesByConfidence.Values.Sum(),
                HotNodes = hotNodes,
                EdgesByConfidence = Buckets.Of(Enum.GetValues<Confidence>(), c => Wire.Of(c), edgesByConfidence),
            },
            Chains = new ChainsSummaryView
            {
                Total = chainsByStatus.Values.Sum(),
                ByStatus = Buckets.Of(Enum.GetValues<ChainStatus>(), s => Wire.Of(s), chainsByStatus),
                WeakestJoin = chainConfidences.Count == 0 ? null : Wire.Of(chainConfidences.Min()),
            },
        };

        return await Response.SuccessAsync(view, "scan summary", HttpStatusCode.OK);
    }

    /// <summary>
    /// One <c>GROUP BY … COUNT(*)</c>, materialized as a dictionary.
    /// </summary>
    /// <remarks>
    /// Grouped and projected before materializing, so the database returns one row per distinct
    /// value rather than one row per record. The result carries only the values that actually
    /// occurred — <see cref="Buckets"/> is what fills in the zeroes.
    /// </remarks>
    private static async Task<Dictionary<TKey, int>> CountByAsync<TRow, TKey>(
        IQueryable<TRow> rows, Expression<Func<TRow, TKey>> key, CancellationToken ct)
        where TKey : notnull
    {
        var grouped = await rows
            .GroupBy(key)
            .Select(g => new { Value = g.Key, Count = g.Count() })
            .ToListAsync(ct);

        return grouped.ToDictionary(g => g.Value, g => g.Count);
    }
}

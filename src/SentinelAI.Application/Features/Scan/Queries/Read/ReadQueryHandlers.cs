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

/// <summary>
/// Shared guards for every read endpoint (SEC-40).
/// </summary>
/// <remarks>
/// <para>
/// The task's own warning is "forgetting tenant scoping on read endpoints — a read leak is
/// still a leak", and the way to not forget is to have one place that cannot be skipped rather
/// than five handlers that each remember. Every read goes through
/// <see cref="AuthorizeScanAsync"/>.
/// </para>
/// <para>
/// A scan belonging to another tenant answers <b>404, not 403</b>. A 403 would confirm the scan
/// exists, which is itself the leak — the caller learns a valid id and that someone else owns
/// it. Indistinguishable from "no such scan" is the only safe answer.
/// </para>
/// </remarks>
internal static class ReadGuard
{
    /// <summary>
    /// Confirms the caller may read, and that this scan is theirs. Returns the failure to send
    /// back, or null with the tenant id when the read may proceed.
    /// </summary>
    public static async Task<(Response? Failure, Guid TenantId)> AuthorizeScanAsync(
        IUnitOfWork unitOfWork, ICallerContext caller, Guid scanJobId, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return (await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized), Guid.Empty);

        if (!caller.HasScope(AuthScopes.ScanRead))
            return (await Response.FailureAsync($"the '{AuthScopes.ScanRead}' scope is required", HttpStatusCode.Forbidden), Guid.Empty);

        var tenantId = caller.TenantId.Value;

        var job = await unitOfWork.ScanJobRepository.GetForTenantAsync(scanJobId, tenantId, ct);
        if (job is null)
            return (await Response.FailureAsync($"no scan job '{scanJobId}'", HttpStatusCode.NotFound), Guid.Empty);

        return (null, tenantId);
    }

    /// <summary>
    /// Confirms the caller may read, without naming a particular resource. For the list endpoints,
    /// which have no id to check ownership of — the tenant they return <em>is</em> the answer.
    /// </summary>
    /// <remarks>
    /// Split out rather than folded into <see cref="AuthorizeScanAsync"/> with a nullable id, so
    /// that the per-resource ownership check cannot be skipped by passing null. A guard that does
    /// less when an argument is absent is a guard someone will eventually call with the argument
    /// absent by accident.
    /// </remarks>
    public static async Task<(Response? Failure, Guid TenantId)> AuthorizeTenantAsync(
        ICallerContext caller, string scope)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return (await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized), Guid.Empty);

        if (!caller.HasScope(scope))
            return (await Response.FailureAsync($"the '{scope}' scope is required", HttpStatusCode.Forbidden), Guid.Empty);

        return (null, caller.TenantId.Value);
    }
}

// ---- bundle ----------------------------------------------------------------------------

public sealed class GetBundleQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<GetBundleQuery, Response>
{
    public async Task<Response> Handle(GetBundleQuery request, CancellationToken ct)
    {
        var (failure, tenantId) = await ReadGuard.AuthorizeScanAsync(unitOfWork, caller, request.ScanJobId, ct);
        if (failure is not null) return failure;

        var job = await unitOfWork.ScanJobRepository.GetForTenantAsync(request.ScanJobId, tenantId, ct);

        var bundle = await unitOfWork.Repository<ScanBundle>()
            .GetTableAsNotTracked()
            .FirstOrDefaultAsync(b => b.ScanJobId == request.ScanJobId, ct);

        if (bundle is null)
            return await Response.FailureAsync($"scan '{request.ScanJobId}' has no bundle record", HttpStatusCode.NotFound);

        // The provenance record deliberately outlives the bytes it describes (SEC-35): the
        // manifest and hash stay auditable after the bundle itself has been purged.
        return await Response.SuccessAsync(
            BundleView.From(bundle, job?.BundlePurged ?? false), "bundle provenance", HttpStatusCode.OK);
    }
}

// ---- findings --------------------------------------------------------------------------

public sealed class GetFindingsQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<GetFindingsQuery, Response>
{
    public async Task<Response> Handle(GetFindingsQuery request, CancellationToken ct)
    {
        var (failure, _) = await ReadGuard.AuthorizeScanAsync(unitOfWork, caller, request.ScanJobId, ct);
        if (failure is not null) return failure;

        var limit = Cursor.Clamp(request.Limit);

        var query = unitOfWork.Repository<Finding>()
            .GetTableAsNotTracked()
            .Where(f => f.ScanJobId == request.ScanJobId);

        if (request.Layer is { Length: > 0 })
        {
            if (!Enum.TryParse<Layer>(request.Layer, ignoreCase: true, out var layer))
                return await Response.FailureAsync($"'{request.Layer}' is not a layer (code, dep, infra)", HttpStatusCode.BadRequest);

            query = query.Where(f => f.Layer == layer);
        }

        if (request.MinSeverity is { } minSeverity)
        {
            if (minSeverity is < 0 or > 4)
                return await Response.FailureAsync("min_severity must be between 0 and 4", HttpStatusCode.BadRequest);

            query = query.Where(f => f.Severity >= minSeverity);
        }

        if (request.Cursor is { Length: > 0 })
        {
            if (!Cursor.TryDecode(request.Cursor, out var after))
                return await Response.FailureAsync("the cursor is not valid", HttpStatusCode.BadRequest);

            query = query.Where(f => f.Id.CompareTo(after) > 0);
        }

        // One row more than asked for: its presence is what says another page exists. Counting
        // the whole table instead would be a second query for an answer this already gives.
        var rows = await query.OrderBy(f => f.Id).Take(limit + 1).ToListAsync(ct);

        var page = Page(rows, limit, f => f.Id, FindingView.From);

        return await Response.SuccessAsync(page, "findings", HttpStatusCode.OK);
    }

    internal static CursorPage<TView> Page<TRow, TView>(
        List<TRow> rows, int limit, Func<TRow, Guid> idOf, Func<TRow, TView> project) =>
        Page(rows, limit, row => Cursor.Encode(idOf(row)), project);

    /// <summary>
    /// The same paging for a list whose cursor is not a bare id — see
    /// <see cref="Cursor.Encode(DateTime, Guid)"/> for why a time-ordered list needs one.
    /// </summary>
    internal static CursorPage<TView> Page<TRow, TView>(
        List<TRow> rows, int limit, Func<TRow, string> cursorOf, Func<TRow, TView> project)
    {
        var hasMore = rows.Count > limit;
        var items = hasMore ? rows.Take(limit).ToList() : rows;

        return CursorPage<TView>.Of(
            [.. items.Select(project)],
            hasMore && items.Count > 0 ? cursorOf(items[^1]) : null,
            limit);
    }
}

// ---- graph -----------------------------------------------------------------------------

public sealed class GetGraphQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<GetGraphQuery, Response>
{
    /// <summary>
    /// Most nodes this endpoint will return whole.
    /// </summary>
    /// <remarks>
    /// A ceiling rather than a page, because a partial graph is not a smaller answer but a
    /// wrong one. A scan over this is refused with a message saying so — which is information
    /// the caller can act on, unlike a silently truncated graph that renders as a smaller
    /// system than the one that was scanned.
    /// </remarks>
    public const int MaxNodes = 5_000;

    public async Task<Response> Handle(GetGraphQuery request, CancellationToken ct)
    {
        var (failure, _) = await ReadGuard.AuthorizeScanAsync(unitOfWork, caller, request.ScanJobId, ct);
        if (failure is not null) return failure;

        var nodes = await unitOfWork.Repository<GraphNode>()
            .GetTableAsNotTracked()
            .Where(n => n.ScanJobId == request.ScanJobId)
            .OrderBy(n => n.NodeKey)
            .ToListAsync(ct);

        if (nodes.Count > MaxNodes)
        {
            return await Response.FailureAsync(
                $"this graph has {nodes.Count} nodes, more than the {MaxNodes} this endpoint returns whole",
                HttpStatusCode.RequestEntityTooLarge);
        }

        var edges = await unitOfWork.Repository<GraphEdge>()
            .GetTableAsNotTracked()
            .Where(e => e.ScanJobId == request.ScanJobId)
            .ToListAsync(ct);

        var keysById = nodes.ToDictionary(n => n.Id, n => n.NodeKey);

        var view = new GraphView
        {
            ScanJobId = request.ScanJobId.ToString(),
            Nodes = [.. nodes.Select(GraphNodeView.From)],
            Edges = [.. edges.Select(e => GraphEdgeView.Of(e, keysById))],
        };

        return await Response.SuccessAsync(view, "resource graph", HttpStatusCode.OK);
    }
}

// ---- chains ----------------------------------------------------------------------------

public sealed class GetChainsQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<GetChainsQuery, Response>
{
    public async Task<Response> Handle(GetChainsQuery request, CancellationToken ct)
    {
        var (failure, _) = await ReadGuard.AuthorizeScanAsync(unitOfWork, caller, request.ScanJobId, ct);
        if (failure is not null) return failure;

        var limit = Cursor.Clamp(request.Limit);

        var query = unitOfWork.Repository<Chain>()
            .GetTableAsNotTracked()
            .Where(c => c.ScanJobId == request.ScanJobId);

        if (request.Cursor is { Length: > 0 })
        {
            if (!Cursor.TryDecode(request.Cursor, out var after))
                return await Response.FailureAsync("the cursor is not valid", HttpStatusCode.BadRequest);

            query = query.Where(c => c.Id.CompareTo(after) > 0);
        }

        var rows = await query
            .Include(c => c.ChainHops)
                .ThenInclude(h => h.Edge)
            .OrderBy(c => c.Id)
            .Take(limit + 1)
            .ToListAsync(ct);

        // Node keys for the hops, resolved in one query rather than per hop.
        var keysById = await NodeKeysAsync(unitOfWork, request.ScanJobId, ct);

        var page = GetFindingsQueryHandler.Page(rows, limit, c => c.Id, c => ChainView.From(c, keysById));

        return await Response.SuccessAsync(page, "candidate chains", HttpStatusCode.OK);
    }

    internal static async Task<Dictionary<Guid, string>> NodeKeysAsync(
        IUnitOfWork unitOfWork, Guid scanJobId, CancellationToken ct) =>
        await unitOfWork.Repository<GraphNode>()
            .GetTableAsNotTracked()
            .Where(n => n.ScanJobId == scanJobId)
            .ToDictionaryAsync(n => n.Id, n => n.NodeKey, ct);
}

// ---- report ----------------------------------------------------------------------------

public sealed class GetReportQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<GetReportQuery, Response>
{
    public async Task<Response> Handle(GetReportQuery request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        // A different scope from the scan reads: a report is the adjudicated narrative, and a
        // token allowed to poll scan status is not automatically allowed to read it.
        if (!caller.HasScope(AuthScopes.ReportRead))
            return await Response.FailureAsync($"the '{AuthScopes.ReportRead}' scope is required", HttpStatusCode.Forbidden);

        // The tenant query filter scopes this: another tenant's report is simply not found.
        var report = await unitOfWork.Repository<Report>()
            .GetTableAsNotTracked()
            .Include(r => r.Citations)
            .FirstOrDefaultAsync(r => r.Id == request.ReportId, ct);

        if (report is null)
            return await Response.FailureAsync($"no report '{request.ReportId}'", HttpStatusCode.NotFound);

        var job = await unitOfWork.ScanJobRepository
            .GetForTenantAsync(report.ScanJobId, caller.TenantId.Value, ct);

        var chains = await unitOfWork.Repository<Chain>()
            .GetTableAsNotTracked()
            .Where(c => c.ScanJobId == report.ScanJobId)
            .Include(c => c.ChainHops)
                .ThenInclude(h => h.Edge)
            .OrderBy(c => c.Priority)
            .ToListAsync(ct);

        var keysById = await GetChainsQueryHandler.NodeKeysAsync(unitOfWork, report.ScanJobId, ct);

        var view = new ReportView
        {
            ReportId = report.Id.ToString(),
            ScanJobId = report.ScanJobId.ToString(),
            Framing = report.Framing,
            Summary = report.Summary,
            CorpusVersion = job?.CorpusVersion ?? string.Empty,
            CreatedAt = report.CreatedAt,
            Retained = report.Retained,
            Chains = [.. chains.Select(c => ChainView.From(c, keysById))],
            Citations = [.. report.Citations.Select(CitationView.From)],
            Cost = ReportCostView.From(report),
        };

        return await Response.SuccessAsync(view, "draft audit", HttpStatusCode.OK);
    }
}

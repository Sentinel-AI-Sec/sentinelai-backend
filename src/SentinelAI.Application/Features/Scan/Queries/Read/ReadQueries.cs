using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Queries.Read;

/// <summary>Bundle provenance for one scan (SEC-40).</summary>
public sealed record GetBundleQuery(Guid ScanJobId) : IRequest<Response>;

/// <summary>
/// A page of normalized findings, newest last.
/// </summary>
/// <param name="Layer">Optional filter: <c>code</c>, <c>dep</c> or <c>infra</c>.</param>
/// <param name="MinSeverity">Optional filter: only findings at or above this 0–4 severity.</param>
public sealed record GetFindingsQuery(
    Guid ScanJobId,
    string? Cursor = null,
    int? Limit = null,
    string? Layer = null,
    int? MinSeverity = null) : IRequest<Response>;

/// <summary>
/// The whole resource graph for one scan — nodes and edges together.
/// </summary>
/// <remarks>
/// Deliberately not paginated. A page of a graph has edges pointing at nodes that are not in
/// it, which a renderer cannot draw and a reader cannot interpret: half a graph is not a
/// smaller graph, it is a wrong one. Bounded by a node cap instead, and a scan that exceeds it
/// is told so rather than silently truncated.
/// </remarks>
public sealed record GetGraphQuery(Guid ScanJobId) : IRequest<Response>;

/// <summary>A page of candidate chains with their hops, highest priority first.</summary>
public sealed record GetChainsQuery(
    Guid ScanJobId,
    string? Cursor = null,
    int? Limit = null) : IRequest<Response>;

/// <summary>One draft audit, with its chains and citations.</summary>
public sealed record GetReportQuery(Guid ReportId) : IRequest<Response>;

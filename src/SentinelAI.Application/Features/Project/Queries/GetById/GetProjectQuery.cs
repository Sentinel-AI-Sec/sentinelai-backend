using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Project.Queries.GetById;

/// <summary>
/// One project of the caller's tenant, by id.
/// </summary>
/// <remarks>
/// <para>
/// <c>GET /v1/projects/{id}</c> is in the API design document's endpoint table
/// (<c>SentinelAI_API_Design_V2.1.md</c> §4) and was the one row of it never implemented. It is
/// not made redundant by <c>GET /v1/projects</c>: a scan, a report and a PR comment all carry a
/// <c>project_id</c> and nothing else about the repository, so any screen that starts from a scan
/// and wants to name the repository it came from either resolves that id directly or downloads
/// every project the tenant has to find one row.
/// </para>
/// <para>
/// A project belonging to another tenant answers <c>404</c>, not <c>403</c> — same rule as the
/// scan reads. A 403 confirms the id is real and merely someone else's, which is itself the leak.
/// </para>
/// </remarks>
public sealed record GetProjectQuery(Guid ProjectId) : IRequest<Response>;

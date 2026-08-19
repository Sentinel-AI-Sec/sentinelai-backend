using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Project.Queries.List;

/// <summary>
/// Every project the caller's tenant owns.
/// </summary>
/// <remarks>
/// It takes no parameters, and that is the point: the only scoping input is the tenant on the
/// verified token, so there is no field a caller could set to widen the result. The reason this
/// exists rather than being left to <c>POST /v1/projects</c>'s response is the GitHub Action's
/// <c>project-id</c> input — a workflow author who no longer has the create response needs a way
/// to read the id back that does not involve guessing at a GUID.
/// </remarks>
public sealed record ListProjectsQuery : IRequest<Response>;

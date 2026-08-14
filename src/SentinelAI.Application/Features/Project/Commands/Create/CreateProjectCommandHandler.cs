using System.Net;
using MediatR;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;
using ProjectEntity = SentinelAI.Domain.Models.Project;

namespace SentinelAI.Application.Features.Project.Commands.Create;

/// <summary>
/// Creates the <see cref="ProjectEntity"/> row <c>POST /v1/scans</c> resolves
/// <c>metadata.project_id</c> against. See <see cref="CreateProjectCommand"/> for why this is an
/// endpoint rather than something registration does.
/// </summary>
/// <remarks>
/// The <c>Project</c> type is aliased because the feature folder is <c>Features/Project</c>, and
/// inside <c>SentinelAI.Application.Features.Project.*</c> the bare name <c>Project</c> binds to
/// the namespace rather than the entity. The alias is the alternative to renaming the folder away
/// from the aggregate it is about.
/// </remarks>
public class CreateProjectCommandHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<CreateProjectCommand, Response>
{
    /// <summary>
    /// The branch assumed when the caller names none.
    /// </summary>
    /// <remarks>
    /// Applied here, once, rather than as an initializer on the entity: the entity's default is
    /// <c>string.Empty</c>, and a row that reached the database with an empty branch would be a
    /// project nobody can diff a pull request against. Putting the default at the one place a
    /// project is created means there is exactly one answer to "what does an unspecified branch
    /// mean", and it is visible in a code review.
    /// </remarks>
    public const string DefaultBranch = "main";

    public async Task<Response> Handle(CreateProjectCommand request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        // [Authorize(Roles = "admin")] already gates the route; re-checked here so the handler is
        // provably correct on its own, exactly as PurgeScanBundleCommandHandler does. It also
        // closes the machine-token case: the Action's token carries scan:write and no role at all,
        // and a token that can submit scans must not be able to register new repositories.
        if (caller.Role != Roles.Admin)
            return await Response.FailureAsync("this action requires the admin role", HttpStatusCode.Forbidden);

        var tenantId = caller.TenantId.Value;
        var repoUrl = request.RepoUrl.Trim();

        var existing = await FindByRepoUrlAsync(tenantId, repoUrl);
        if (existing is not null)
        {
            // 409 carrying the existing id, not 400 and not a second row. The Action's
            // 'project-id' input has to stay stable across re-runs of whatever provisioning
            // script called this, and the useful answer to "this repo is already registered" is
            // the id it was registered as.
            return await Response.FailureAsync(
                ProjectResponse.From(existing),
                $"'{repoUrl}' is already registered for this tenant",
                HttpStatusCode.Conflict);
        }

        var project = new ProjectEntity
        {
            Id = Guid.CreateVersion7(),
            // From the verified token, never from the request body — SEC-32. A tenant id the
            // caller could supply is the whole of a cross-tenant write.
            TenantId = tenantId,
            RepoUrl = repoUrl,
            DefaultBranch = request.DefaultBranch?.Trim() ?? DefaultBranch,
            GithubInstallationId = request.GithubInstallationId?.Trim(),
        };

        await unitOfWork.Repository<ProjectEntity>().AddAsync(project);
        await unitOfWork.CompleteAsync();

        return await Response.SuccessAsync(
            ProjectResponse.From(project), "project created", HttpStatusCode.Created);
    }

    /// <summary>
    /// The tenant's project for this repository, if it has one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The comparison is done in memory, on purpose. <c>(tenant_id, repo_url)</c> carries a unique
    /// index, but whether that index treats <c>.../Repo</c> and <c>.../repo</c> as the same value
    /// is decided by the database's collation — case-insensitive on a default SQL Server
    /// deployment, case-sensitive on one somebody tightened, and case-sensitive again on the
    /// in-memory provider the tests run against. Deferring to the collation would mean the
    /// duplicate check behaves differently in three places, and the failure mode is the one this
    /// endpoint exists to prevent: two project ids for one repository, so the id the Action was
    /// configured with is no longer the id the scans arrive under.
    /// </para>
    /// <para>
    /// Loading the tenant's projects to do it is affordable because the set is small by
    /// construction — one row per repository a customer scans — and the global query filter has
    /// already narrowed the read to this tenant before the predicate is applied.
    /// </para>
    /// </remarks>
    private async Task<ProjectEntity?> FindByRepoUrlAsync(Guid tenantId, string repoUrl)
    {
        var projects = await unitOfWork.Repository<ProjectEntity>()
            .GetWhereAsync(p => p.TenantId == tenantId);

        return projects.FirstOrDefault(
            p => string.Equals(p.RepoUrl, repoUrl, StringComparison.OrdinalIgnoreCase));
    }
}

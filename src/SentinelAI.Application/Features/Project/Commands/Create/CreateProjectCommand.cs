using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Project.Commands.Create;

/// <summary>
/// Registers a repository this tenant may submit scans for, and hands back the id the GitHub
/// Action passes as its <c>project-id</c> input.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why an endpoint rather than a project auto-created at registration.</b> Until this command
/// existed, nothing anywhere in <c>src/</c> constructed a <see cref="Domain.Models.Project"/> — only
/// tests did, directly against the <c>DbContext</c> — so a tenant created through
/// <c>POST /v1/auth/register</c> could never satisfy <c>POST /v1/scans</c>'s
/// <c>metadata.project_id</c>, and the product's primary path needed a hand-written SQL insert.
/// Both fixes close that; they are not equivalent.
/// </para>
/// <para>
/// A project <em>is</em> a repository: <c>repo_url</c> is what every scan's provenance hangs off,
/// and it is the only thing that distinguishes two projects of the same tenant. Registration knows
/// an email and a tenant name and nothing about any repository, so a project created there would
/// have to carry an empty or invented <c>repo_url</c>. A scan attributed to a repository that does
/// not exist is worse than a scan that cannot start: the second failure is visible at the moment
/// it happens, and the first is discovered when someone reads a report and cannot find the code.
/// </para>
/// <para>
/// A tenant with two repositories needs two projects regardless, so this command has to exist
/// either way; auto-creating one at registration would only add a first project that behaves
/// differently from every other project — no repo, created by nobody, and impossible to describe
/// in the docs without an exception.
/// </para>
/// <para>
/// <b>The Action needs a stable id, and stability is what makes this safe to call twice.</b>
/// <c>(tenant_id, repo_url)</c> is unique, so re-registering a repository returns
/// <c>409 Conflict</c> carrying the <em>existing</em> project id rather than minting a second
/// project for the same repository. A workflow author who lost the create response recovers the id
/// from <c>GET /v1/projects</c> or by re-issuing this call; neither can change the id a running
/// workflow already passes.
/// </para>
/// </remarks>
/// <param name="RepoUrl">The repository this project scans, e.g. <c>https://github.com/org/repo</c>.</param>
/// <param name="DefaultBranch">
/// The branch a scan is compared against. Null means <c>main</c> — see
/// <c>CreateProjectCommandHandler.DefaultBranch</c> for why the default is applied there and not
/// silently in the entity.
/// </param>
/// <param name="GithubInstallationId">
/// The GitHub App installation this repository is reachable through, when there is one. Null for a
/// repository scanned by a workflow using a machine token, which is the path the Action takes
/// today.
/// </param>
public sealed record CreateProjectCommand(
    string RepoUrl,
    string? DefaultBranch,
    string? GithubInstallationId) : IRequest<Response>;

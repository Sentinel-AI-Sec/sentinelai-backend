using ProjectEntity = SentinelAI.Domain.Models.Project;

namespace SentinelAI.Application.Features.Project;

/// <summary>
/// A project on the wire.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ProjectId"/> is a string rather than a <see cref="Guid"/> for the same reason
/// <c>SubmitScanResponse.ScanJobId</c> is: this value is copied by a human out of a response body
/// and pasted into a workflow file as the Action's <c>project-id</c> input. A serializer that
/// decides to render a GUID differently between two versions would silently invalidate every
/// workflow that was configured from an older response.
/// </para>
/// <para>
/// <see cref="TenantId"/> is deliberately absent. The caller already knows their tenant — it is in
/// the token they authenticated with — and echoing it back is a field a future bug could populate
/// from the row rather than the token, which is the shape of a cross-tenant disclosure.
/// </para>
/// </remarks>
public sealed record ProjectResponse
{
    public required string ProjectId { get; init; }
    public required string RepoUrl { get; init; }
    public required string DefaultBranch { get; init; }
    public string? GithubInstallationId { get; init; }

    public static ProjectResponse From(ProjectEntity project) => new()
    {
        ProjectId = project.Id.ToString(),
        RepoUrl = project.RepoUrl,
        DefaultBranch = project.DefaultBranch,
        GithubInstallationId = project.GithubInstallationId,
    };
}

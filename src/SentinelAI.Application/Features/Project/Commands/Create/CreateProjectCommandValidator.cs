using FluentValidation;

namespace SentinelAI.Application.Features.Project.Commands.Create;

/// <summary>
/// Shape checks only. Whether the repository exists, and whether this tenant may scan it, are
/// questions no validator can answer.
/// </summary>
public sealed class CreateProjectCommandValidator : AbstractValidator<CreateProjectCommand>
{
    /// <summary>
    /// Matches the column width <c>ProjectConfiguration</c> declares. Both numbers exist because
    /// the index on <c>(tenant_id, repo_url)</c> needs a bounded column, and a request that would
    /// be truncated to fit it has to be refused here rather than stored as a different URL than
    /// the one the caller sent.
    /// </summary>
    public const int MaxRepoUrlLength = 500;

    public const int MaxBranchLength = 255;

    public const int MaxInstallationIdLength = 100;

    public CreateProjectCommandValidator()
    {
        RuleFor(x => x.RepoUrl)
            .NotEmpty()
            .MaximumLength(MaxRepoUrlLength)
            // Absolute, not merely non-empty. A relative or bare value ("org/repo") would be
            // stored, would be unique, and would then appear in a report as the provenance of a
            // finding with no way to resolve it back to a repository.
            .Must(BeAnAbsoluteHttpUrl)
            .WithMessage("repo_url must be an absolute http(s) URL, e.g. https://github.com/org/repo");

        // Optional, but not "optional and then anything": a caller who sends the field is stating
        // a branch, and an empty or whitespace string is not one. Silently swapping it for the
        // default would hide a workflow that is interpolating an unset variable.
        RuleFor(x => x.DefaultBranch)
            .NotEmpty()
            .MaximumLength(MaxBranchLength)
            .When(x => x.DefaultBranch is not null);

        RuleFor(x => x.GithubInstallationId)
            .NotEmpty()
            .MaximumLength(MaxInstallationIdLength)
            .When(x => x.GithubInstallationId is not null);
    }

    private static bool BeAnAbsoluteHttpUrl(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
}

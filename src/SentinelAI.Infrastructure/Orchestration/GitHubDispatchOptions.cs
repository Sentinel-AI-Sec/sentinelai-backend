namespace SentinelAI.Infrastructure.Orchestration;

/// <summary>
/// What the API needs in order to ask GitHub to run a repository's scan workflow.
/// </summary>
public sealed class GitHubDispatchOptions
{
    public const string SectionName = "Scanning:GitHub";

    /// <summary>
    /// A token with <c>actions: write</c> on the repositories this tenant scans.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Empty means the feature is off: <c>POST /v1/scans/dispatch</c> answers <c>503</c> naming
    /// this key, and the console keeps offering the bundle upload instead. That is the same
    /// fail-visible rule <c>Billing:SecretKey</c> and <c>KeyVault:Uri</c> follow, and it is what
    /// lets a fresh clone and the whole test suite run with no GitHub credential at all.
    /// </para>
    /// <para>
    /// <b>A single token is a deliberate simplification, and a temporary one.</b> It scans
    /// whatever repositories that token can reach, which is correct while every project belongs to
    /// the same organisation and wrong the moment a second customer arrives.
    /// <c>Project.GithubInstallationId</c> exists for the proper answer — a GitHub App installed
    /// per customer, exchanging an installation id for a short-lived token — and is unused so far.
    /// Until then this token must be scoped to the organisation's own repositories and nothing
    /// else.
    /// </para>
    /// </remarks>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// The workflow file to dispatch, as it is named under <c>.github/workflows/</c>.
    /// </summary>
    /// <remarks>
    /// A convention rather than a lookup. GitHub will dispatch by file name, and requiring every
    /// scanned repository to call its workflow the same thing is a cheaper contract than storing a
    /// per-project file name that somebody has to keep in step with a rename.
    /// </remarks>
    public string WorkflowFile { get; set; } = "sentinelai.yml";

    /// <summary>GitHub's API host. Overridable for GitHub Enterprise.</summary>
    public string ApiBaseUrl { get; set; } = "https://api.github.com";

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Token);
}

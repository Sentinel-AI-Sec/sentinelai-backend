namespace SentinelAI.Application.Abstractions;

/// <summary>
/// Asks a repository's CI to run a scan of one branch.
/// </summary>
/// <remarks>
/// <para>
/// <b>This system does not scan anything itself, and that is the point.</b> The scanners — OSV,
/// Roslyn, Checkov, Trivy — run inside the GitHub Action, next to a checkout of the customer's
/// code, and the API only ever receives the bundle they produce. Moving them server-side would
/// mean cloning arbitrary customer repositories into the API container and executing tooling over
/// them, which is a different security posture from the one <c>Sandboxed_Processing.md</c>
/// describes.
/// </para>
/// <para>
/// So "scan this branch" is not a new pipeline. It is a request to the CI that already knows how
/// to do it, and everything downstream — the upload, the graph, the debate, the report — happens
/// exactly as it does on a pull request, through the same machine token and the same endpoints.
/// </para>
/// </remarks>
public interface IScanDispatcher
{
    /// <summary>Whether a dispatch could be attempted at all — i.e. a credential is configured.</summary>
    bool IsConfigured { get; }

    /// <summary>
    /// Asks the repository at <paramref name="repoUrl"/> to run its scan workflow against
    /// <paramref name="gitRef"/>.
    /// </summary>
    /// <remarks>
    /// Returns what happened rather than throwing, because every failure here is somebody's
    /// configuration — a missing token, a repository that has no such workflow, a branch that does
    /// not exist — and each needs a different sentence in front of the person who pressed the
    /// button.
    /// </remarks>
    Task<ScanDispatchResult> DispatchAsync(string repoUrl, string gitRef, CancellationToken ct = default);
}

/// <summary>The outcome of asking CI to run a scan.</summary>
/// <param name="Accepted">True when the workflow run was queued.</param>
/// <param name="Reason">
/// Why not, when it was not. Written for the person who pressed the button, not for a log.
/// </param>
public sealed record ScanDispatchResult(bool Accepted, string? Reason = null)
{
    public static ScanDispatchResult Ok() => new(true);

    public static ScanDispatchResult Rejected(string reason) => new(false, reason);
}

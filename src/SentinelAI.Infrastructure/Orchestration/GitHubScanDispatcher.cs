using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;

namespace SentinelAI.Infrastructure.Orchestration;

/// <summary>
/// <see cref="IScanDispatcher"/> over GitHub's workflow-dispatch endpoint.
/// </summary>
/// <remarks>
/// <para>
/// One call: <c>POST /repos/{owner}/{repo}/actions/workflows/{file}/dispatches</c> with a
/// <c>ref</c>. GitHub answers <c>204</c> and nothing else — no run id, no URL — so this cannot
/// hand back a scan job id, and the caller does not get one. The Action creates the scan job when
/// it uploads its bundle, which is a few minutes later; the console finds it by listing the
/// project's scans, exactly as it would for a scan somebody started by opening a pull request.
/// </para>
/// <para>
/// <b>The branch is the <c>ref</c>.</b> That is why this needs no workflow inputs and no change to
/// any repository being scanned: <c>workflow_dispatch</c> already takes the ref to run against,
/// and a branch name is one.
/// </para>
/// </remarks>
public sealed class GitHubScanDispatcher(
    HttpClient http,
    IOptionsMonitor<GitHubDispatchOptions> options,
    ILogger<GitHubScanDispatcher> logger) : IScanDispatcher
{
    public bool IsConfigured => options.CurrentValue.IsConfigured;

    public async Task<ScanDispatchResult> DispatchAsync(
        string repoUrl, string gitRef, CancellationToken ct = default)
    {
        var settings = options.CurrentValue;

        if (!settings.IsConfigured)
            return ScanDispatchResult.Rejected(
                "starting a scan from here is not configured for this deployment");

        var (owner, repo) = ParseOwnerRepo(repoUrl);

        if (owner is null || repo is null)
            return ScanDispatchResult.Rejected(
                $"'{repoUrl}' is not a repository URL an owner and name can be read from");

        var url = $"{settings.ApiBaseUrl.TrimEnd('/')}/repos/{owner}/{repo}" +
                  $"/actions/workflows/{settings.WorkflowFile}/dispatches";

        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(new { @ref = gitRef }),
        };

        // Read per call rather than on a configured client, so a rotated token takes effect
        // without a restart — the same reason the JWT key and the Stripe key are read lazily.
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.Token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");

        HttpResponseMessage response;

        try
        {
            response = await http.SendAsync(request, ct);
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning(ex, "Could not reach GitHub to dispatch a scan of {Owner}/{Repo}.", owner, repo);
            return ScanDispatchResult.Rejected("could not reach GitHub");
        }

        using (response)
        {
            if (response.StatusCode == HttpStatusCode.NoContent)
            {
                logger.LogInformation(
                    "Dispatched {Workflow} on {Owner}/{Repo} at ref {Ref}.",
                    settings.WorkflowFile, owner, repo, gitRef);

                return ScanDispatchResult.Ok();
            }

            var body = await response.Content.ReadAsStringAsync(ct);

            logger.LogWarning(
                "GitHub refused to dispatch {Workflow} on {Owner}/{Repo} at ref {Ref}: {Status} {Body}",
                settings.WorkflowFile, owner, repo, gitRef, (int)response.StatusCode, body);

            // Translated rather than passed through. GitHub answers 404 both for "no such
            // workflow" and for "your token cannot see this repository", and a caller staring at
            // a 404 for a repository they can see in their browser has no way to tell which.
            return ScanDispatchResult.Rejected(response.StatusCode switch
            {
                HttpStatusCode.NotFound =>
                    $"no '{settings.WorkflowFile}' workflow on {owner}/{repo}, or the configured "
                    + "credential cannot see that repository",
                HttpStatusCode.UnprocessableEntity =>
                    $"'{gitRef}' is not a branch on {owner}/{repo}, or its workflow does not "
                    + "allow being started manually (it needs a workflow_dispatch trigger)",
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden =>
                    "the configured GitHub credential is not allowed to start workflows on that "
                    + "repository",
                _ => $"GitHub refused the request ({(int)response.StatusCode})",
            });
        }
    }

    /// <summary>
    /// Pulls <c>owner</c> and <c>repo</c> out of a repository URL.
    /// </summary>
    /// <remarks>
    /// Handles the three shapes a <c>Project.RepoUrl</c> is realistically written in — with and
    /// without <c>.git</c>, and with an <c>scp</c>-style SSH prefix — because the field is free
    /// text a human typed into <c>POST /v1/projects</c>.
    /// </remarks>
    internal static (string? Owner, string? Repo) ParseOwnerRepo(string repoUrl)
    {
        if (string.IsNullOrWhiteSpace(repoUrl)) return (null, null);

        var trimmed = repoUrl.Trim();

        // git@github.com:owner/repo.git -> owner/repo.git
        var scp = trimmed.IndexOf(':');
        if (trimmed.StartsWith("git@", StringComparison.OrdinalIgnoreCase) && scp > 0)
            trimmed = trimmed[(scp + 1)..];
        else if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
            trimmed = uri.AbsolutePath;

        var parts = trimmed
            .Trim('/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (parts.Length < 2) return (null, null);

        // The last two segments, so a self-hosted path prefix does not shift the pair.
        var owner = parts[^2];
        var repo = parts[^1];

        if (repo.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
            repo = repo[..^4];

        return string.IsNullOrWhiteSpace(owner) || string.IsNullOrWhiteSpace(repo)
            ? (null, null)
            : (owner, repo);
    }
}

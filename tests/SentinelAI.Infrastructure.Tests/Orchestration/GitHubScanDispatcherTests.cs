using SentinelAI.Infrastructure.Orchestration;

namespace SentinelAI.Infrastructure.Tests.Orchestration;

/// <summary>
/// Reading an owner and a repository name out of a project's URL.
/// </summary>
/// <remarks>
/// Tested directly rather than through the endpoint, for the reason this assembly exists: it is a
/// string-format detail, not API, and a parser proven only through a whole pipeline is a parser
/// whose edge cases are untested. <c>Project.RepoUrl</c> is free text a human typed into
/// <c>POST /v1/projects</c>, so the forms people actually write are all handled rather than
/// assumed away — and an unparseable one has to fail as a refusal with a reason, not as a request
/// to <c>github.com//dispatches</c>.
/// </remarks>
public class GitHubScanDispatcherTests
{
    [Theory]
    [InlineData("https://github.com/example/repo", "example", "repo")]
    [InlineData("https://github.com/example/repo.git", "example", "repo")]
    [InlineData("https://github.com/example/repo/", "example", "repo")]
    [InlineData("  https://github.com/example/repo  ", "example", "repo")]
    [InlineData("git@github.com:example/repo.git", "example", "repo")]
    [InlineData("https://github.com/Example-Org/Repo.Name", "Example-Org", "Repo.Name")]
    public void An_owner_and_name_are_read_from_the_shapes_people_write(
        string url, string owner, string repo)
        => Assert.Equal((owner, repo), GitHubScanDispatcher.ParseOwnerRepo(url));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-url")]
    [InlineData("https://github.com/onlyowner")]
    public void A_url_with_no_owner_and_name_yields_neither(string url)
        => Assert.Equal((null, null), GitHubScanDispatcher.ParseOwnerRepo(url));
}

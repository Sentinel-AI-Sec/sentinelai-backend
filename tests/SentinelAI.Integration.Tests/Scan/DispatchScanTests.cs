using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// <c>POST /v1/scans/dispatch</c> — starting a scan from the console with a project and a branch,
/// instead of the GitHub Action's whole payload.
/// </summary>
/// <remarks>
/// What is worth pinning here is ours, not GitHub's: that another tenant's project is
/// indistinguishable from one that does not exist, that the Action's machine token cannot ask for
/// a scan, and that the branch actually sent is the one the caller asked for — or the project's
/// default when they named none, which is what makes this a two-field screen.
/// </remarks>
public class DispatchScanTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;

    public DispatchScanTests(ScanApiFactory factory) => _factory = factory;

    private (HttpClient Client, FakeScanDispatcher Dispatcher) NewClient(bool configured = true)
    {
        var dispatcher = new FakeScanDispatcher { IsConfigured = configured };

        var host = _factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IScanDispatcher>();
            services.AddSingleton<IScanDispatcher>(dispatcher);
        }));

        return (host.CreateClient(), dispatcher);
    }

    private static HttpClient As(HttpClient client, Guid tenantId, string? role)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            role is null
                // A machine token: scan:write and no role at all, exactly what the Action carries.
                ? TestJwt.Create(tenantId, scopes: [AuthScopes.ScanWrite])
                : TestJwt.Create(tenantId, Guid.CreateVersion7(), role));

        return client;
    }

    private async Task<Guid> SeedProjectAsync(Guid tenantId, string defaultBranch = "main")
    {
        var project = new Project
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            RepoUrl = "https://github.com/example/repo",
            DefaultBranch = defaultBranch,
        };

        await _factory.SeedAsync(db => db.Projects.Add(project));

        return project.Id;
    }

    private static Task<HttpResponseMessage> DispatchAsync(
        HttpClient client, Guid projectId, string? gitRef = null)
        => client.PostAsJsonAsync("/v1/scans/dispatch", new { projectId, gitRef });

    [Fact]
    public async Task An_unauthenticated_caller_cannot_start_a_scan()
    {
        var (client, dispatcher) = NewClient();

        var response = await DispatchAsync(client, Guid.CreateVersion7());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(dispatcher.Calls);
    }

    /// <summary>
    /// The Action's own token cannot ask for another scan.
    /// </summary>
    /// <remarks>
    /// It carries <c>scan:write</c> and no role, which is exactly what it needs to *upload* a scan
    /// it has already run. Letting it request one as well is a loop with a scan job at every turn
    /// of it, and the Action has no reason to want that.
    /// </remarks>
    [Fact]
    public async Task A_machine_token_cannot_start_a_scan()
    {
        var (client, dispatcher) = NewClient();
        var tenant = Guid.CreateVersion7();
        var projectId = await SeedProjectAsync(tenant);

        var response = await DispatchAsync(As(client, tenant, role: null), projectId);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(dispatcher.Calls);
    }

    /// <summary>
    /// Another tenant's project answers exactly as one that does not exist.
    /// </summary>
    /// <remarks>
    /// A distinguishable 403 would make this endpoint a way to test whether a project id belongs
    /// to somebody — which is the whole of a tenant-enumeration bug.
    /// </remarks>
    [Fact]
    public async Task Another_tenants_project_is_indistinguishable_from_one_that_does_not_exist()
    {
        var (client, dispatcher) = NewClient();
        var theirs = await SeedProjectAsync(Guid.CreateVersion7());

        var mine = As(client, Guid.CreateVersion7(), Roles.Admin);

        var onTheirs = await DispatchAsync(mine, theirs);
        var onNothing = await DispatchAsync(mine, Guid.CreateVersion7());

        Assert.Equal(HttpStatusCode.NotFound, onTheirs.StatusCode);
        Assert.Equal(onNothing.StatusCode, onTheirs.StatusCode);
        Assert.Empty(dispatcher.Calls);
    }

    [Fact]
    public async Task A_named_branch_is_the_one_dispatched()
    {
        var (client, dispatcher) = NewClient();
        var tenant = Guid.CreateVersion7();
        var projectId = await SeedProjectAsync(tenant, defaultBranch: "main");

        var response = await DispatchAsync(As(client, tenant, Roles.Analyst), projectId, "feature/x");

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(("https://github.com/example/repo", "feature/x"), Assert.Single(dispatcher.Calls));
    }

    /// <summary>
    /// Naming no branch scans the project's default — the two-click case this endpoint exists for.
    /// </summary>
    [Fact]
    public async Task No_branch_means_the_projects_default_branch()
    {
        var (client, dispatcher) = NewClient();
        var tenant = Guid.CreateVersion7();
        var projectId = await SeedProjectAsync(tenant, defaultBranch: "dev");

        var response = await DispatchAsync(As(client, tenant, Roles.Admin), projectId);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(("https://github.com/example/repo", "dev"), Assert.Single(dispatcher.Calls));

        // Echoed back, so the screen can say which branch it scanned without guessing.
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"git_ref\":\"dev\"", body);
    }

    /// <summary>
    /// With no credential configured the endpoint says so, rather than failing as a server error.
    /// </summary>
    /// <remarks>
    /// 503 naming the setting, so the console can offer the bundle upload instead — the same
    /// fail-visible rule the Stripe key follows.
    /// </remarks>
    [Fact]
    public async Task An_unconfigured_deployment_reports_that_rather_than_failing()
    {
        var (client, dispatcher) = NewClient(configured: false);
        var tenant = Guid.CreateVersion7();
        var projectId = await SeedProjectAsync(tenant);

        var response = await DispatchAsync(As(client, tenant, Roles.Admin), projectId);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Empty(dispatcher.Calls);
    }

    /// <summary>A refusal from CI is reported as one, with the reason CI gave.</summary>
    [Fact]
    public async Task A_refusal_from_ci_carries_its_reason()
    {
        var (client, dispatcher) = NewClient();
        dispatcher.Result = ScanDispatchResult.Rejected("'nope' is not a branch on example/repo");

        var tenant = Guid.CreateVersion7();
        var projectId = await SeedProjectAsync(tenant);

        var response = await DispatchAsync(As(client, tenant, Roles.Admin), projectId, "nope");

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Contains("is not a branch", await response.Content.ReadAsStringAsync());
    }
}

/// <summary>A dispatcher that records what it was asked to do and never leaves the process.</summary>
internal sealed class FakeScanDispatcher : IScanDispatcher
{
    public bool IsConfigured { get; init; } = true;

    public ScanDispatchResult Result { get; set; } = ScanDispatchResult.Ok();

    /// <summary>Every (repo, ref) pair asked for. Empty is a meaningful assertion.</summary>
    public List<(string RepoUrl, string GitRef)> Calls { get; } = [];

    public Task<ScanDispatchResult> DispatchAsync(
        string repoUrl, string gitRef, CancellationToken ct = default)
    {
        Calls.Add((repoUrl, gitRef));
        return Task.FromResult(Result);
    }
}

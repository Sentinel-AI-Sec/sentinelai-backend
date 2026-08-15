using System.Net;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.ReadApi;

/// <summary>
/// The task's own warning, tested: <em>"Forgetting tenant scoping on read endpoints. A read leak
/// is still a leak. Every GET must filter by tenant."</em>
/// </summary>
/// <remarks>
/// <para>
/// Every endpoint is probed with a valid token for a <em>different</em> tenant and a real scan
/// id belonging to this one. The expected answer is <b>404, not 403</b>. That distinction is the
/// substance of the test: a 403 says "this exists and is not yours", which hands the caller a
/// confirmed id and the knowledge that someone else owns it. 404 is indistinguishable from a
/// scan that was never created.
/// </para>
/// <para>
/// Written as a theory over every route so a sixth read endpoint added later has to be added
/// here too — the list is the checklist.
/// </para>
/// </remarks>
public class ReadApiTenantIsolationTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;
    private readonly ReadApiFixture _fixture;

    public ReadApiTenantIsolationTests(ScanApiFactory factory)
    {
        _factory = factory;
        _fixture = new ReadApiFixture(factory);
        _fixture.SeedAsync().GetAwaiter().GetResult();
    }

    public static TheoryData<string> ScanRoutes() => new()
    {
        "bundle", "findings", "graph", "chains",
    };

    [Theory]
    [MemberData(nameof(ScanRoutes))]
    public async Task Another_tenant_gets_not_found_never_forbidden(string route)
    {
        var response = await _fixture
            .ForeignClient(AuthScopes.ScanRead)
            .GetAsync($"/v1/scans/{_fixture.ScanJobId}/{route}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Another_tenant_cannot_read_a_report()
    {
        var response = await _fixture
            .ForeignClient(AuthScopes.ReportRead)
            .GetAsync($"/v1/reports/{_fixture.ReportId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(ScanRoutes))]
    public async Task An_anonymous_caller_is_refused(string route)
    {
        var response = await _fixture
            .AnonymousClient()
            .GetAsync($"/v1/scans/{_fixture.ScanJobId}/{route}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(ScanRoutes))]
    public async Task A_token_without_the_scan_read_scope_is_refused(string route)
    {
        // Scopes exist in AuthScopes and were enforced nowhere before SEC-40. A token that can
        // submit scans is not thereby allowed to read their contents.
        var response = await _fixture
            .Client(AuthScopes.ScanWrite)
            .GetAsync($"/v1/scans/{_fixture.ScanJobId}/{route}");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Reading_a_report_needs_its_own_scope()
    {
        // report:read is separate from scan:read on purpose: the adjudicated narrative is not
        // the same material as the scan's status.
        var response = await _fixture
            .Client(AuthScopes.ScanRead)
            .GetAsync($"/v1/reports/{_fixture.ReportId}");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_scan_that_does_not_exist_answers_the_same_as_one_owned_by_another_tenant()
    {
        // The two must be indistinguishable, or the difference between them is the leak.
        var missing = await _fixture.Client(AuthScopes.ScanRead)
            .GetAsync($"/v1/scans/{Guid.NewGuid()}/findings");

        var foreign = await _fixture.ForeignClient(AuthScopes.ScanRead)
            .GetAsync($"/v1/scans/{_fixture.ScanJobId}/findings");

        Assert.Equal(missing.StatusCode, foreign.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }
}

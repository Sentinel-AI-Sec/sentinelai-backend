using System.Net;
using System.Net.Http.Headers;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Retention;

/// <summary>
/// <c>DELETE /v1/account</c> through the real API — real JWT pipeline, real role gate, real
/// purge (SEC-35).
/// </summary>
/// <remarks>
/// The service-level tests prove the deletion is complete and correctly ordered. These prove
/// the only other thing that matters about the most destructive endpoint in the system: that
/// not everyone can reach it, and that a caller can never point it at somebody else's account.
/// </remarks>
public class AccountDeletionEndpointTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;

    public AccountDeletionEndpointTests(ScanApiFactory factory) => _factory = factory;

    private HttpClient ClientFor(string? token)
    {
        var client = _factory.CreateClient();

        if (token is not null)
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        return client;
    }

    private async Task SeedProjectAsync(Guid tenantId) =>
        await _factory.SeedAsync(db => db.Projects.Add(new Project
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            RepoUrl = "https://example.test/repo",
            DefaultBranch = "main",
        }));

    [Fact]
    public async Task An_anonymous_caller_cannot_delete_an_account()
    {
        var response = await ClientFor(null).DeleteAsync("/v1/account");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(Roles.Viewer)]
    [InlineData(Roles.Analyst)]
    public async Task A_non_admin_cannot_delete_an_account(string role)
    {
        var token = TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(), role: role);

        var response = await ClientFor(token).DeleteAsync("/v1/account");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_machine_token_with_no_role_cannot_delete_an_account()
    {
        // Machine tokens carry scopes, never a role. Account deletion is a human decision, so
        // a CI token that can submit scans must not also be able to destroy the account.
        var token = TestJwt.Create(Guid.NewGuid(), scopes: [AuthScopes.ScanWrite]);

        var response = await ClientFor(token).DeleteAsync("/v1/account");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task An_admin_deletes_their_own_account_and_its_data_goes()
    {
        var tenantId = Guid.NewGuid();
        await SeedProjectAsync(tenantId);

        var token = TestJwt.Create(tenantId, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await ClientFor(token).DeleteAsync("/v1/account");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await _factory.SeedAsync(db =>
            Assert.Empty(db.Projects.IgnoreQueryFilters().Where(p => p.TenantId == tenantId).ToList()));
    }

    [Fact]
    public async Task Deleting_one_account_leaves_another_intact()
    {
        // The endpoint takes no id, so there is no request that could name the wrong tenant —
        // this pins that property rather than trusting the absence of a parameter.
        var mine = Guid.NewGuid();
        var theirs = Guid.NewGuid();
        await SeedProjectAsync(mine);
        await SeedProjectAsync(theirs);

        var token = TestJwt.Create(mine, userId: Guid.NewGuid(), role: Roles.Admin);
        var response = await ClientFor(token).DeleteAsync("/v1/account");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await _factory.SeedAsync(db =>
        {
            Assert.Empty(db.Projects.IgnoreQueryFilters().Where(p => p.TenantId == mine).ToList());
            Assert.NotEmpty(db.Projects.IgnoreQueryFilters().Where(p => p.TenantId == theirs).ToList());
        });
    }

    [Fact]
    public async Task Deleting_an_account_that_holds_nothing_still_succeeds()
    {
        // A tenant with no data is not an error case: "delete everything I have" is satisfied
        // by having nothing, and returning 404 would leak whether an account holds data.
        var token = TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await ClientFor(token).DeleteAsync("/v1/account");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}

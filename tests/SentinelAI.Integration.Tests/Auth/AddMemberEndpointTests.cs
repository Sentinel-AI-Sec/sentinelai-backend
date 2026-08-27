using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Auth;

/// <summary>
/// <c>POST /v1/account/members</c> through the real API — bringing an existing account into the
/// caller's tenant.
/// </summary>
/// <remarks>
/// The endpoint moves a user between tenants and can destroy the one they leave, so the tests
/// that matter are the ones pinning when it refuses. Three of them are about not stranding data:
/// the last admin of a populated tenant cannot be taken, a tenant emptied by the move is purged,
/// and one that still has members is not.
/// </remarks>
public class AddMemberEndpointTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;

    public AddMemberEndpointTests(ScanApiFactory factory) => _factory = factory;

    private HttpClient ClientFor(string? token)
    {
        var client = _factory.CreateClient();

        if (token is not null)
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        return client;
    }

    private async Task SeedUserAsync(Guid tenantId, Guid userId, string role, string email) =>
        await _factory.SeedAsync(db => db.Users.Add(new User
        {
            Id = userId,
            TenantId = tenantId,
            Email = email,
            PasswordHash = "not-a-real-hash",
            Role = role,
            CreatedAt = DateTime.UtcNow,
        }));

    private async Task<User?> UserAsync(Guid userId)
    {
        User? user = null;
        await _factory.SeedAsync(db =>
            user = db.Users.IgnoreQueryFilters().AsNoTracking().FirstOrDefault(u => u.Id == userId));
        return user;
    }

    private static Task<HttpResponseMessage> AddAsync(HttpClient client, string email, string role) =>
        client.PostAsJsonAsync("/v1/account/members", new { email, role });

    private static async Task<JsonElement> DataOfAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return body.GetProperty("data");
    }

    /// <summary>A unique address per test — Users.Email is globally unique.</summary>
    private static string NewEmail() => $"u{Guid.NewGuid():N}@example.test";

    // ---- the role gate ----------------------------------------------------------------

    [Fact]
    public async Task An_anonymous_caller_cannot_add_a_member()
    {
        var response = await AddAsync(ClientFor(null), NewEmail(), Roles.Viewer);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(Roles.Viewer)]
    [InlineData(Roles.Analyst)]
    public async Task A_non_admin_cannot_add_a_member(string role)
    {
        var theirTenant = Guid.NewGuid();
        var target = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(theirTenant, target, Roles.Admin, email);

        var token = TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(), role: role);

        var response = await AddAsync(ClientFor(token), email, Roles.Analyst);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(theirTenant, (await UserAsync(target))!.TenantId);
    }

    [Fact]
    public async Task A_machine_token_cannot_add_a_member()
    {
        var theirTenant = Guid.NewGuid();
        var target = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(theirTenant, target, Roles.Admin, email);

        var token = TestJwt.Create(Guid.NewGuid(), scopes: [AuthScopes.ScanWrite]);

        var response = await AddAsync(ClientFor(token), email, Roles.Admin);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(theirTenant, (await UserAsync(target))!.TenantId);
    }

    // ---- the address must already be registered ----------------------------------------

    [Fact]
    public async Task An_unregistered_address_is_refused_and_no_account_is_created()
    {
        // The endpoint never provisions. A 404 here rather than a 201 is what stops an admin
        // manufacturing an account whose password only they know.
        var email = NewEmail();
        var token = TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), email, Roles.Admin);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

        await _factory.SeedAsync(db =>
            Assert.Empty(db.Users.IgnoreQueryFilters().Where(u => u.Email == email).ToList()));
    }

    [Fact]
    public async Task A_malformed_address_is_refused_as_malformed_rather_than_as_not_found()
    {
        var token = TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), "not-an-email", Roles.Viewer);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task The_address_is_matched_regardless_of_case()
    {
        // Registration lower-cases before storing, so an admin who types a capital must still
        // find the account rather than be told it does not exist.
        var theirTenant = Guid.NewGuid();
        var target = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(theirTenant, target, Roles.Admin, email);

        var mine = Guid.NewGuid();
        var token = TestJwt.Create(mine, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), email.ToUpperInvariant(), Roles.Viewer);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(mine, (await UserAsync(target))!.TenantId);
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("Admin")]
    public async Task An_unrecognised_role_is_refused(string role)
    {
        var theirTenant = Guid.NewGuid();
        var target = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(theirTenant, target, Roles.Admin, email);

        var token = TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), email, role);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(theirTenant, (await UserAsync(target))!.TenantId);
    }

    // ---- already here -------------------------------------------------------------------

    [Fact]
    public async Task A_member_of_this_tenant_is_refused_as_a_conflict()
    {
        var mine = Guid.NewGuid();
        var existing = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(mine, existing, Roles.Viewer, email);

        var token = TestJwt.Create(mine, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), email, Roles.Analyst);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        // Refused outright, so the role they already hold is untouched — this is not a
        // back-door role change.
        Assert.Equal(Roles.Viewer, (await UserAsync(existing))!.Role);
    }

    [Fact]
    public async Task An_admin_cannot_add_themselves()
    {
        // Falls out of the already-a-member rule rather than being a special case.
        var mine = Guid.NewGuid();
        var me = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(mine, me, Roles.Admin, email);

        var token = TestJwt.Create(mine, userId: me, role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), email, Roles.Viewer);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(Roles.Admin, (await UserAsync(me))!.Role);
    }

    // ---- not stranding the tenant they leave --------------------------------------------

    [Fact]
    public async Task The_last_admin_of_a_populated_tenant_cannot_be_taken()
    {
        // Their colleagues would keep their data and lose the only account able to administer it.
        var theirTenant = Guid.NewGuid();
        var theirAdmin = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(theirTenant, theirAdmin, Roles.Admin, email);
        await SeedUserAsync(theirTenant, Guid.NewGuid(), Roles.Analyst, NewEmail());

        var token = TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), email, Roles.Analyst);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(theirTenant, (await UserAsync(theirAdmin))!.TenantId);
    }

    [Fact]
    public async Task A_non_admin_can_be_taken_from_a_populated_tenant_which_survives()
    {
        var theirTenant = Guid.NewGuid();
        var theirAdmin = Guid.NewGuid();
        var target = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(theirTenant, theirAdmin, Roles.Admin, NewEmail());
        await SeedUserAsync(theirTenant, target, Roles.Viewer, email);

        var mine = Guid.NewGuid();
        var token = TestJwt.Create(mine, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), email, Roles.Analyst);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(mine, (await UserAsync(target))!.TenantId);

        var data = await DataOfAsync(response);
        Assert.False(data.GetProperty("previousTenantPurged").GetBoolean());

        // The admin left behind, and their tenant, are untouched.
        Assert.Equal(theirTenant, (await UserAsync(theirAdmin))!.TenantId);
        await _factory.SeedAsync(db =>
            Assert.NotEmpty(db.Tenants.IgnoreQueryFilters().Where(t => t.Id == theirTenant).ToList()));
    }

    [Fact]
    public async Task An_admin_of_a_populated_tenant_can_be_taken_when_another_admin_remains()
    {
        var theirTenant = Guid.NewGuid();
        var target = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(theirTenant, target, Roles.Admin, email);
        await SeedUserAsync(theirTenant, Guid.NewGuid(), Roles.Admin, NewEmail());

        var mine = Guid.NewGuid();
        var token = TestJwt.Create(mine, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), email, Roles.Viewer);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(mine, (await UserAsync(target))!.TenantId);
    }

    // ---- the emptied tenant is destroyed -------------------------------------------------

    [Fact]
    public async Task Taking_a_tenants_only_member_purges_that_tenant_and_its_data()
    {
        // A tenant with no users can never have a token issued for it again, so anything left in
        // it would be unreachable and undeletable forever.
        var theirTenant = Guid.NewGuid();
        var target = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(theirTenant, target, Roles.Admin, email);
        await _factory.SeedAsync(db => db.Projects.Add(new Project
        {
            Id = Guid.CreateVersion7(),
            TenantId = theirTenant,
            RepoUrl = "https://example.test/leaving",
            DefaultBranch = "main",
        }));

        var mine = Guid.NewGuid();
        var token = TestJwt.Create(mine, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), email, Roles.Analyst);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var data = await DataOfAsync(response);
        Assert.True(data.GetProperty("previousTenantPurged").GetBoolean());
        Assert.True(data.GetProperty("previousTenantRowsDeleted").GetInt32() > 0);

        await _factory.SeedAsync(db =>
        {
            Assert.Empty(db.Projects.IgnoreQueryFilters().Where(p => p.TenantId == theirTenant).ToList());
            Assert.Empty(db.Tenants.IgnoreQueryFilters().Where(t => t.Id == theirTenant).ToList());
        });

        // The moved account itself survives the purge — it is in the new tenant by then.
        var moved = await UserAsync(target);
        Assert.NotNull(moved);
        Assert.Equal(mine, moved!.TenantId);
        Assert.Equal(Roles.Analyst, moved.Role);
    }

    [Theory]
    [InlineData(Roles.Admin)]
    [InlineData(Roles.Analyst)]
    [InlineData(Roles.Viewer)]
    public async Task The_member_arrives_holding_the_role_that_was_asked_for(string role)
    {
        var theirTenant = Guid.NewGuid();
        var target = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(theirTenant, target, Roles.Admin, email);

        var mine = Guid.NewGuid();
        var token = TestJwt.Create(mine, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), email, role);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(role, (await DataOfAsync(response)).GetProperty("member").GetProperty("role").GetString());
        Assert.Equal(role, (await UserAsync(target))!.Role);
    }

    [Fact]
    public async Task Moving_a_member_revokes_the_sessions_stamped_with_their_old_tenant()
    {
        // Their access token carries the OLD tenant claim. Left alone, they would keep reading
        // their former organisation's data until the refresh token expired.
        var theirTenant = Guid.NewGuid();
        var target = Guid.NewGuid();
        var tokenId = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(theirTenant, target, Roles.Admin, email);
        await SeedUserAsync(theirTenant, Guid.NewGuid(), Roles.Admin, NewEmail());
        await _factory.SeedAsync(db => db.RefreshTokens.Add(new RefreshToken
        {
            Id = tokenId,
            TenantId = theirTenant,
            UserId = target,
            TokenHash = $"hash-{tokenId}",
            ExpiresAt = DateTime.UtcNow.AddDays(30),
            CreatedAt = DateTime.UtcNow,
        }));

        var token = TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await AddAsync(ClientFor(token), email, Roles.Viewer);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, (await DataOfAsync(response)).GetProperty("sessionsRevoked").GetInt32());

        await _factory.SeedAsync(db =>
        {
            var stored = db.RefreshTokens.IgnoreQueryFilters().First(t => t.Id == tokenId);
            Assert.NotNull(stored.RevokedAt);
        });
    }

    [Fact]
    public async Task An_added_member_then_appears_in_the_tenants_member_list()
    {
        // The two endpoints have to agree: a move that the list does not reflect is a move that
        // did not happen as far as any screen is concerned.
        var theirTenant = Guid.NewGuid();
        var email = NewEmail();
        await SeedUserAsync(theirTenant, Guid.NewGuid(), Roles.Admin, email);

        var mine = Guid.NewGuid();
        var token = TestJwt.Create(mine, userId: Guid.NewGuid(), role: Roles.Admin);
        var client = ClientFor(token);

        await AddAsync(client, email, Roles.Analyst);

        var list = await client.GetAsync("/v1/account/members");
        var emails = (await DataOfAsync(list))
            .EnumerateArray()
            .Select(m => m.GetProperty("email").GetString())
            .ToList();

        Assert.Contains(email, emails);
    }
}

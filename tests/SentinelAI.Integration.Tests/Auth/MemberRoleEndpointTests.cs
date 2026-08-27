using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Auth;

/// <summary>
/// <c>GET /v1/account/members</c> and <c>PATCH /v1/account/members/{id}</c> through the real API
/// — real JWT pipeline, real role gate, real rows.
/// </summary>
/// <remarks>
/// These are the endpoints that make <c>analyst</c> and <c>viewer</c> reachable at all: before
/// them, <c>POST /v1/auth/register</c> was the only thing that ever wrote <c>User.Role</c>, and it
/// always wrote <c>admin</c>. What is worth pinning is therefore not that the happy path works but
/// that the two ways privilege escalation could be smuggled in are closed — a caller cannot point
/// the endpoint at another tenant's user, and cannot use it on themselves.
/// </remarks>
public class MemberRoleEndpointTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;

    public MemberRoleEndpointTests(ScanApiFactory factory) => _factory = factory;

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

    private async Task<string?> RoleInDbAsync(Guid userId)
    {
        string? role = null;
        await _factory.SeedAsync(db =>
            role = db.Users.IgnoreQueryFilters().FirstOrDefault(u => u.Id == userId)?.Role);
        return role;
    }

    private static async Task<JsonElement> DataOfAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return body.GetProperty("data");
    }

    private static HttpRequestMessage Patch(Guid userId, string role) =>
        new(HttpMethod.Patch, $"/v1/account/members/{userId}")
        {
            Content = JsonContent.Create(new { role }),
        };

    // ---- the role gate ----------------------------------------------------------------

    [Fact]
    public async Task An_anonymous_caller_cannot_list_members()
    {
        var response = await ClientFor(null).GetAsync("/v1/account/members");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(Roles.Viewer)]
    [InlineData(Roles.Analyst)]
    public async Task A_non_admin_cannot_list_members(string role)
    {
        var token = TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(), role: role);

        var response = await ClientFor(token).GetAsync("/v1/account/members");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData(Roles.Viewer)]
    [InlineData(Roles.Analyst)]
    public async Task A_non_admin_cannot_change_a_role(string role)
    {
        var tenantId = Guid.NewGuid();
        var target = Guid.NewGuid();
        await SeedUserAsync(tenantId, target, Roles.Viewer, $"{target}@example.test");

        var token = TestJwt.Create(tenantId, userId: Guid.NewGuid(), role: role);

        var response = await ClientFor(token).SendAsync(Patch(target, Roles.Admin));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(Roles.Viewer, await RoleInDbAsync(target));
    }

    [Fact]
    public async Task A_machine_token_with_no_role_cannot_change_a_role()
    {
        // The Action's token holds scan:write and no role at all. Granting roles is a human
        // decision; a CI token that can submit scans must not be able to make itself an admin.
        var tenantId = Guid.NewGuid();
        var target = Guid.NewGuid();
        await SeedUserAsync(tenantId, target, Roles.Viewer, $"{target}@example.test");

        var token = TestJwt.Create(tenantId, scopes: [AuthScopes.ScanWrite]);

        var response = await ClientFor(token).SendAsync(Patch(target, Roles.Admin));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(Roles.Viewer, await RoleInDbAsync(target));
    }

    // ---- tenant isolation -------------------------------------------------------------

    [Fact]
    public async Task Members_of_another_tenant_are_never_in_the_list()
    {
        var mine = Guid.NewGuid();
        var theirs = Guid.NewGuid();
        var myUser = Guid.NewGuid();
        var theirUser = Guid.NewGuid();
        await SeedUserAsync(mine, myUser, Roles.Analyst, $"{myUser}@mine.test");
        await SeedUserAsync(theirs, theirUser, Roles.Admin, $"{theirUser}@theirs.test");

        var token = TestJwt.Create(mine, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await ClientFor(token).GetAsync("/v1/account/members");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var emails = (await DataOfAsync(response))
            .EnumerateArray()
            .Select(m => m.GetProperty("email").GetString())
            .ToList();

        Assert.Contains($"{myUser}@mine.test", emails);
        Assert.DoesNotContain($"{theirUser}@theirs.test", emails);
    }

    [Fact]
    public async Task An_admin_cannot_change_a_role_in_another_tenant()
    {
        // 404 rather than 403, and the distinction is the test: 403 would confirm the id names a
        // real account somewhere, turning an admin-held endpoint into a user-id oracle across
        // the whole install.
        var mine = Guid.NewGuid();
        var theirs = Guid.NewGuid();
        var theirUser = Guid.NewGuid();
        await SeedUserAsync(theirs, theirUser, Roles.Viewer, $"{theirUser}@theirs.test");

        var token = TestJwt.Create(mine, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await ClientFor(token).SendAsync(Patch(theirUser, Roles.Admin));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(Roles.Viewer, await RoleInDbAsync(theirUser));
    }

    [Fact]
    public async Task A_user_id_that_does_not_exist_answers_the_same_404()
    {
        var token = TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await ClientFor(token).SendAsync(Patch(Guid.NewGuid(), Roles.Analyst));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ---- the lockout defence ----------------------------------------------------------

    [Fact]
    public async Task An_admin_cannot_change_their_own_role()
    {
        // This one rule is the whole last-admin-lockout defence: demoting an admin requires a
        // second admin, who is still an admin afterwards, so a tenant can never reach zero.
        var tenantId = Guid.NewGuid();
        var me = Guid.NewGuid();
        await SeedUserAsync(tenantId, me, Roles.Admin, $"{me}@example.test");

        var token = TestJwt.Create(tenantId, userId: me, role: Roles.Admin);

        var response = await ClientFor(token).SendAsync(Patch(me, Roles.Viewer));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(Roles.Admin, await RoleInDbAsync(me));
    }

    // ---- the happy path ---------------------------------------------------------------

    [Theory]
    [InlineData(Roles.Analyst)]
    [InlineData(Roles.Viewer)]
    [InlineData(Roles.Admin)]
    public async Task An_admin_assigns_a_role_to_another_member(string newRole)
    {
        var tenantId = Guid.NewGuid();
        var target = Guid.NewGuid();
        await SeedUserAsync(tenantId, target, Roles.Viewer, $"{target}@example.test");

        var token = TestJwt.Create(tenantId, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await ClientFor(token).SendAsync(Patch(target, newRole));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(newRole, (await DataOfAsync(response)).GetProperty("role").GetString());
        Assert.Equal(newRole, await RoleInDbAsync(target));
    }

    [Fact]
    public async Task The_receipt_reports_the_scopes_the_new_role_grants()
    {
        // The difference between analyst and viewer is entirely scan:write, which a role name
        // alone does not say — so the response carries it.
        var tenantId = Guid.NewGuid();
        var target = Guid.NewGuid();
        await SeedUserAsync(tenantId, target, Roles.Viewer, $"{target}@example.test");

        var token = TestJwt.Create(tenantId, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await ClientFor(token).SendAsync(Patch(target, Roles.Analyst));

        var scopes = (await DataOfAsync(response))
            .GetProperty("scopes")
            .EnumerateArray()
            .Select(s => s.GetString())
            .ToList();

        Assert.Contains(AuthScopes.ScanWrite, scopes);
    }

    [Fact]
    public async Task A_members_row_never_carries_a_password_hash()
    {
        // MemberResponse projects explicitly rather than returning the entity. This is what
        // catches the day someone shortens that projection back to the row.
        var tenantId = Guid.NewGuid();
        var target = Guid.NewGuid();
        await SeedUserAsync(tenantId, target, Roles.Analyst, $"{target}@example.test");

        var token = TestJwt.Create(tenantId, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await ClientFor(token).GetAsync("/v1/account/members");
        var raw = await response.Content.ReadAsStringAsync();

        Assert.DoesNotContain("passwordHash", raw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("not-a-real-hash", raw);
    }

    [Fact]
    public async Task Assigning_the_role_a_member_already_holds_succeeds_unchanged()
    {
        // A retried request whose response was lost should not fail the second time.
        var tenantId = Guid.NewGuid();
        var target = Guid.NewGuid();
        await SeedUserAsync(tenantId, target, Roles.Analyst, $"{target}@example.test");

        var token = TestJwt.Create(tenantId, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await ClientFor(token).SendAsync(Patch(target, Roles.Analyst));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Roles.Analyst, await RoleInDbAsync(target));
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("Admin")]
    [InlineData("")]
    public async Task An_unrecognised_role_is_refused_rather_than_stored(string role)
    {
        // "Admin" is in here on purpose. The value is written verbatim into a JWT claim and
        // compared verbatim by [Authorize(Roles = ...)], so storing it would create an account
        // that authorises nothing and reads, in every UI, as an admin.
        var tenantId = Guid.NewGuid();
        var target = Guid.NewGuid();
        await SeedUserAsync(tenantId, target, Roles.Viewer, $"{target}@example.test");

        var token = TestJwt.Create(tenantId, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await ClientFor(token).SendAsync(Patch(target, role));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(Roles.Viewer, await RoleInDbAsync(target));
    }

    // ---- making the change take effect -------------------------------------------------

    [Fact]
    public async Task Changing_a_role_revokes_the_members_live_refresh_tokens()
    {
        // Without this the demoted member keeps renewing a token carrying the old role for the
        // refresh token's full lifetime — a demotion that does nothing for 30 days.
        var tenantId = Guid.NewGuid();
        var target = Guid.NewGuid();
        var tokenId = Guid.NewGuid();
        await SeedUserAsync(tenantId, target, Roles.Admin, $"{target}@example.test");
        await _factory.SeedAsync(db => db.RefreshTokens.Add(new RefreshToken
        {
            Id = tokenId,
            TenantId = tenantId,
            UserId = target,
            TokenHash = $"hash-{tokenId}",
            ExpiresAt = DateTime.UtcNow.AddDays(30),
            CreatedAt = DateTime.UtcNow,
        }));

        var token = TestJwt.Create(tenantId, userId: Guid.NewGuid(), role: Roles.Admin);

        var response = await ClientFor(token).SendAsync(Patch(target, Roles.Viewer));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await _factory.SeedAsync(db =>
        {
            var stored = db.RefreshTokens.IgnoreQueryFilters().First(t => t.Id == tokenId);
            Assert.NotNull(stored.RevokedAt);
        });
    }

    [Fact]
    public async Task Changing_a_role_leaves_another_members_sessions_alone()
    {
        var tenantId = Guid.NewGuid();
        var target = Guid.NewGuid();
        var bystander = Guid.NewGuid();
        var bystanderToken = Guid.NewGuid();
        await SeedUserAsync(tenantId, target, Roles.Viewer, $"{target}@example.test");
        await SeedUserAsync(tenantId, bystander, Roles.Analyst, $"{bystander}@example.test");
        await _factory.SeedAsync(db => db.RefreshTokens.Add(new RefreshToken
        {
            Id = bystanderToken,
            TenantId = tenantId,
            UserId = bystander,
            TokenHash = $"hash-{bystanderToken}",
            ExpiresAt = DateTime.UtcNow.AddDays(30),
            CreatedAt = DateTime.UtcNow,
        }));

        var token = TestJwt.Create(tenantId, userId: Guid.NewGuid(), role: Roles.Admin);

        await ClientFor(token).SendAsync(Patch(target, Roles.Analyst));

        await _factory.SeedAsync(db =>
        {
            var stored = db.RefreshTokens.IgnoreQueryFilters().First(t => t.Id == bystanderToken);
            Assert.Null(stored.RevokedAt);
        });
    }
}

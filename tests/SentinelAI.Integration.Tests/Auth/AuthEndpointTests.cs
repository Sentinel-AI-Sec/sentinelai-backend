using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Features.Auth;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Integration.Tests.Auth;

/// <summary>
/// Register/login/refresh/logout, proven through the real HTTP pipeline — real password
/// hashing, real token issuance, real <c>[Authorize]</c> enforcement on the other end —
/// rather than by calling a handler directly.
/// </summary>
public class AuthEndpointTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;

    public AuthEndpointTests(ScanApiFactory factory) => _factory = factory;

    private static string UniqueEmail() => $"user-{Guid.NewGuid():N}@example.com";

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private sealed record Envelope<T>(bool IsSuccess, string Message, T? Data);

    private static async Task<Envelope<T>> ReadAsync<T>(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<Envelope<T>>(json, JsonOptions)!;
    }

    [Fact]
    public async Task Register_creates_a_new_tenant_and_the_returned_token_is_usable()
    {
        var client = _factory.CreateClient();
        var email = UniqueEmail();

        var registerResponse = await client.PostAsJsonAsync("/v1/auth/register",
            new { Email = email, Password = "correct-horse-battery-staple", TenantName = "Acme Inc" });

        Assert.Equal(HttpStatusCode.Created, registerResponse.StatusCode);
        var body = await ReadAsync<AuthTokenResponse>(registerResponse);
        Assert.True(body.IsSuccess, body.Message);
        Assert.NotNull(body.Data);
        Assert.NotEmpty(body.Data!.AccessToken);
        Assert.NotEmpty(body.Data.RefreshToken);
        Assert.Equal("admin", body.Data.Role);

        // The full loop: the token this endpoint just issued has to actually work against a
        // real [Authorize] endpoint elsewhere in the app - not just "look like" a token.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.Data.AccessToken);
        var protectedResponse = await client.GetAsync($"/v1/scans/{Guid.NewGuid()}");

        // 404 (no such job), not 401 - proves the token was accepted, not rejected.
        Assert.Equal(HttpStatusCode.NotFound, protectedResponse.StatusCode);
    }

    /// <summary>
    /// A login token has to carry the scopes its role implies, not just a role.
    /// </summary>
    /// <remarks>
    /// This is the hole that let every scan endpoint answer 403 to a perfectly valid admin token:
    /// <c>JwtTokenIssuer</c> issued <c>sub</c>, <c>tenant_id</c>, <c>role</c> and <c>jti</c> and no
    /// <c>scope</c> at all, so <c>HasScope</c> was false for every human user who ever logged in.
    /// The suite missed it because the scan tests mint their own tokens with <c>TestJwt</c> and
    /// hand themselves the scopes — nothing exercised the real issuer. So this asserts through a
    /// scope-gated endpoint: a token that reaches "no such job" got past the gate, and a 403 here
    /// means the regression is back.
    /// </remarks>
    [Fact]
    public async Task The_token_register_issues_carries_the_scopes_its_role_implies()
    {
        var client = _factory.CreateClient();

        var registerResponse = await client.PostAsJsonAsync("/v1/auth/register",
            new { Email = UniqueEmail(), Password = "correct-horse-battery-staple", TenantName = "Acme Inc" });

        var body = await ReadAsync<AuthTokenResponse>(registerResponse);
        Assert.NotNull(body.Data);
        Assert.Contains("scan:write", body.Data!.Scopes);
        Assert.Contains("scan:read", body.Data.Scopes);
        Assert.Contains("report:read", body.Data.Scopes);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.Data.AccessToken);
        var gated = await client.PostAsync($"/v1/scans/{Guid.NewGuid()}/graph", content: null);

        Assert.Equal(HttpStatusCode.NotFound, gated.StatusCode);
    }

    [Fact]
    public async Task Registering_the_same_email_twice_is_rejected()
    {
        var client = _factory.CreateClient();
        var email = UniqueEmail();
        var payload = new { Email = email, Password = "correct-horse-battery-staple", TenantName = "Acme Inc" };

        var first = await client.PostAsJsonAsync("/v1/auth/register", payload);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        var second = await client.PostAsJsonAsync("/v1/auth/register", payload);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Login_with_the_correct_password_succeeds()
    {
        var client = _factory.CreateClient();
        var email = UniqueEmail();
        await client.PostAsJsonAsync("/v1/auth/register",
            new { Email = email, Password = "correct-horse-battery-staple", TenantName = "Acme Inc" });

        var loginResponse = await client.PostAsJsonAsync("/v1/auth/login",
            new { Email = email, Password = "correct-horse-battery-staple" });

        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        var body = await ReadAsync<AuthTokenResponse>(loginResponse);
        Assert.NotEmpty(body.Data!.AccessToken);
    }

    [Fact]
    public async Task Login_with_the_wrong_password_and_login_with_an_unknown_email_look_identical()
    {
        var client = _factory.CreateClient();
        var email = UniqueEmail();
        await client.PostAsJsonAsync("/v1/auth/register",
            new { Email = email, Password = "correct-horse-battery-staple", TenantName = "Acme Inc" });

        var wrongPassword = await client.PostAsJsonAsync("/v1/auth/login",
            new { Email = email, Password = "not-the-right-password" });
        var unknownEmail = await client.PostAsJsonAsync("/v1/auth/login",
            new { Email = UniqueEmail(), Password = "whatever" });

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownEmail.StatusCode);

        var wrongPasswordBody = await ReadAsync<object>(wrongPassword);
        var unknownEmailBody = await ReadAsync<object>(unknownEmail);

        // Same message either way - telling them apart would let an attacker enumerate
        // which emails have an account at all.
        Assert.Equal(unknownEmailBody.Message, wrongPasswordBody.Message);
    }

    [Fact]
    public async Task Refresh_rotates_the_token_and_the_old_one_stops_working()
    {
        var client = _factory.CreateClient();
        var email = UniqueEmail();
        var registerResponse = await client.PostAsJsonAsync("/v1/auth/register",
            new { Email = email, Password = "correct-horse-battery-staple", TenantName = "Acme Inc" });
        var original = (await ReadAsync<AuthTokenResponse>(registerResponse)).Data!;

        var refreshResponse = await client.PostAsJsonAsync("/v1/auth/refresh",
            new { RefreshToken = original.RefreshToken });

        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);
        var rotated = (await ReadAsync<AuthTokenResponse>(refreshResponse)).Data!;
        Assert.NotEqual(original.RefreshToken, rotated.RefreshToken);
        Assert.NotEqual(original.AccessToken, rotated.AccessToken);

        // The token just spent no longer works.
        var reuseResponse = await client.PostAsJsonAsync("/v1/auth/refresh",
            new { RefreshToken = original.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, reuseResponse.StatusCode);
    }

    [Fact]
    public async Task Logout_revokes_the_refresh_token()
    {
        var client = _factory.CreateClient();
        var email = UniqueEmail();
        var registerResponse = await client.PostAsJsonAsync("/v1/auth/register",
            new { Email = email, Password = "correct-horse-battery-staple", TenantName = "Acme Inc" });
        var tokens = (await ReadAsync<AuthTokenResponse>(registerResponse)).Data!;

        var logoutResponse = await client.PostAsJsonAsync("/v1/auth/logout",
            new { RefreshToken = tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, logoutResponse.StatusCode);

        var refreshAfterLogout = await client.PostAsJsonAsync("/v1/auth/refresh",
            new { RefreshToken = tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refreshAfterLogout.StatusCode);
    }

    [Fact]
    public async Task Password_is_never_stored_in_plaintext()
    {
        var client = _factory.CreateClient();
        var email = UniqueEmail();
        const string password = "correct-horse-battery-staple";

        await client.PostAsJsonAsync("/v1/auth/register",
            new { Email = email, Password = password, TenantName = "Acme Inc" });

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        var user = db.Users.IgnoreQueryFilters().Single(u => u.Email == email);

        Assert.NotEmpty(user.PasswordHash);
        Assert.NotEqual(password, user.PasswordHash);
        Assert.DoesNotContain(password, user.PasswordHash);
    }
}

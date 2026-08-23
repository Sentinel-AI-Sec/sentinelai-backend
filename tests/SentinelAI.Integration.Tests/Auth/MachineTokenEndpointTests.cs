using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using SentinelAI.Application.Features.Auth.Commands.MintMachineToken;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Auth;

/// <summary>
/// <c>POST /v1/auth/machine-token</c> — the endpoint that replaced minting the GitHub Action's
/// credential out of band with a script and the API's raw signing key.
/// </summary>
/// <remarks>
/// <para>
/// Every assertion here goes through the real HTTP pipeline rather than calling the handler with
/// a hand-built <c>ICallerContext</c>, for the reason <see cref="AuthAndTenantIsolationTests"/>
/// gives: the properties that matter are enforced by middleware and
/// <c>[Authorize(Roles = ...)]</c>, and a handler-level test cannot prove a 401 or a 403 exists
/// at all.
/// </para>
/// <para>
/// The token is also never inspected by decoding it. What matters is not which claims a
/// <c>JwtSecurityTokenHandler</c> can read back out of it — that would only re-assert what
/// <c>JwtTokenIssuer</c> was just told to write — but what the API does when the token is
/// presented. So the tests present it.
/// </para>
/// </remarks>
public class MachineTokenEndpointTests : IClassFixture<ScanApiFactory>
{
    private readonly ScanApiFactory _factory;

    public MachineTokenEndpointTests(ScanApiFactory factory) => _factory = factory;

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private sealed record Envelope<T>(bool IsSuccess, string Message, T? Data);

    private static async Task<Envelope<T>> ReadAsync<T>(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<Envelope<T>>(json, JsonOptions)!;
    }

    private HttpClient ClientFor(string token)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    /// <summary>Seeds the tenant row the handler checks for before it mints anything.</summary>
    private async Task<Guid> SeedTenantAsync()
    {
        var tenantId = Guid.NewGuid();
        await _factory.SeedAsync(db => db.Tenants.Add(new Tenant
        {
            Id = tenantId,
            Name = "Acme Inc",
            PlanTier = "free",
            CreatedAt = DateTime.UtcNow,
        }));
        return tenantId;
    }

    private async Task<MachineTokenResponse> MintAsync(Guid tenantId)
    {
        var admin = TestJwt.Create(tenantId, Guid.NewGuid(), Roles.Admin, RoleScopes.For(Roles.Admin));

        var response = await ClientFor(admin).PostAsync("/v1/auth/machine-token", content: null);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await ReadAsync<MachineTokenResponse>(response);
        Assert.True(body.IsSuccess, body.Message);
        Assert.NotNull(body.Data);
        return body.Data!;
    }

    // ---- Who may mint one -------------------------------------------------------------

    [Fact]
    public async Task No_token_cannot_mint_one()
    {
        var response = await _factory.CreateClient().PostAsync("/v1/auth/machine-token", content: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData(Roles.Analyst)]
    [InlineData(Roles.Viewer)]
    public async Task Non_admin_roles_cannot_mint_one(string role)
    {
        var tenantId = await SeedTenantAsync();
        var token = TestJwt.Create(tenantId, Guid.NewGuid(), role, RoleScopes.For(role));

        var response = await ClientFor(token).PostAsync("/v1/auth/machine-token", content: null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// The property that keeps a leaked machine token from being a foothold: it cannot mint a
    /// successor for itself, because minting is role-gated and it carries no role at all.
    /// </summary>
    [Fact]
    public async Task A_machine_token_cannot_mint_another_machine_token()
    {
        var tenantId = await SeedTenantAsync();
        var minted = await MintAsync(tenantId);

        var response = await ClientFor(minted.Token).PostAsync("/v1/auth/machine-token", content: null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // ---- What the minted token can and cannot do --------------------------------------

    /// <summary>
    /// The whole point of the endpoint: the value it hands back has to actually authenticate the
    /// Action against the endpoints the Action reaches. Asserted through a scope-gated one —
    /// reaching "no such job" means the token got past both the auth middleware and the scope
    /// check, where a 401 or a 403 would mean it never did.
    /// </summary>
    [Fact]
    public async Task The_minted_token_is_accepted_by_a_scope_gated_endpoint()
    {
        var tenantId = await SeedTenantAsync();
        var minted = await MintAsync(tenantId);

        Assert.Contains(AuthScopes.ScanWrite, minted.Scopes);
        Assert.Contains(AuthScopes.ScanRead, minted.Scopes);
        Assert.Contains(AuthScopes.ReportRead, minted.Scopes);
        Assert.Equal(tenantId, minted.TenantId);
        Assert.True(minted.ExpiresAt > DateTime.UtcNow.AddDays(300),
            "a machine token the Action presents unattended should outlive a login token by a long way");

        var gated = await ClientFor(minted.Token).PostAsync($"/v1/scans/{Guid.NewGuid()}/graph", content: null);

        Assert.Equal(HttpStatusCode.NotFound, gated.StatusCode);
    }

    /// <summary>
    /// Strictly weaker than the admin token that asked for it. Registering a project is
    /// role-gated, so the minted token is refused even though it holds every scope this build
    /// enforces — which is the reason it is issued without a <c>role</c> claim.
    /// </summary>
    [Fact]
    public async Task The_minted_token_is_refused_by_a_role_gated_endpoint()
    {
        var tenantId = await SeedTenantAsync();
        var minted = await MintAsync(tenantId);

        var response = await ClientFor(minted.Token)
            .PostAsJsonAsync("/v1/projects", new { RepoUrl = "https://github.com/acme/app" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// The tenant is the caller's own. There is no parameter to substitute, so this asserts the
    /// only thing that could go wrong: that it is read off the verified token rather than
    /// defaulted or left empty.
    /// </summary>
    [Fact]
    public async Task The_minted_token_acts_for_the_callers_own_tenant()
    {
        var mine = await SeedTenantAsync();
        var theirs = await SeedTenantAsync();

        var minted = await MintAsync(mine);

        Assert.Equal(mine, minted.TenantId);
        Assert.NotEqual(theirs, minted.TenantId);
    }

    /// <summary>
    /// A verified token whose tenant row is gone means the account was deleted (SEC-35) inside
    /// the token's lifetime. 401 rather than a minted credential — a year-long token for a
    /// deleted tenant would outlive the deletion it was supposed to be covered by.
    /// </summary>
    [Fact]
    public async Task A_token_for_a_deleted_tenant_cannot_mint_one()
    {
        var token = TestJwt.Create(
            Guid.NewGuid(), Guid.NewGuid(), Roles.Admin, RoleScopes.For(Roles.Admin));

        var response = await ClientFor(token).PostAsync("/v1/auth/machine-token", content: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// Nothing is persisted, so two calls are two independent credentials rather than the same
    /// one read back — which is what makes "you will not be shown this again" true, and what
    /// makes losing one recoverable by minting another.
    /// </summary>
    [Fact]
    public async Task Minting_twice_yields_two_different_tokens()
    {
        var tenantId = await SeedTenantAsync();

        var first = await MintAsync(tenantId);
        var second = await MintAsync(tenantId);

        Assert.NotEqual(first.Token, second.Token);
    }
}

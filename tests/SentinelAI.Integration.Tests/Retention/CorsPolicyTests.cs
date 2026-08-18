using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using SentinelAI.Api;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Retention;

/// <summary>
/// SEC-42/SEC-40, cross-origin access for the dashboard: only the origins a deployment names
/// may call this API from a browser, and an unconfigured deployment names none.
/// </summary>
/// <remarks>
/// <para>
/// CORS is enforced entirely by the browser, which means nothing else in this repository can
/// catch a mistake here — curl, the other integration tests, and the API's own logs all behave
/// identically whether the policy is right, wrong, or absent. The only signal in a real
/// deployment is a UI that cannot load, and the only signal short of that is this file.
/// </para>
/// <para>
/// These assertions read the response headers rather than the status code on purpose. A
/// disallowed origin is not rejected by the server — the request runs normally and simply comes
/// back without <c>Access-Control-Allow-Origin</c>, at which point the browser discards the
/// response. Asserting on the status would pass no matter what the policy did.
/// </para>
/// </remarks>
public class CorsPolicyTests
{
    private const string AllowedOrigin = "https://dashboard.sentinelai.test";
    private const string DisallowedOrigin = "https://attacker.example";

    private const string AnyScanUrl = "/v1/scans/00000000-0000-0000-0000-000000000000";

    private const string AllowOriginHeader = "Access-Control-Allow-Origin";

    /// <summary>
    /// The standard test host with one origin permitted, as a deployment would configure it.
    /// </summary>
    /// <remarks>
    /// Layered with <c>WithWebHostBuilder</c> for the same reason
    /// <see cref="TransportSecurityTests"/> does: <c>ScanApiFactory</c> is sealed, and this
    /// needs extra configuration rather than different behaviour. The indexed key is the array
    /// binding an environment-variable deployment uses (<c>Cors__AllowedOrigins__0</c>).
    /// </remarks>
    private static WebApplicationFactory<Program> WithAllowedOrigin(ScanApiFactory factory) =>
        factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    [$"{DependencyInjection.CorsAllowedOriginsKey}:0"] = AllowedOrigin,
                })));

    [Fact]
    public async Task A_configured_origin_is_allowed()
    {
        using var factory = new ScanApiFactory();
        using var configured = WithAllowedOrigin(factory);
        using var client = configured.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, AnyScanUrl);
        request.Headers.Add("Origin", AllowedOrigin);

        var response = await client.SendAsync(request);

        Assert.True(response.Headers.Contains(AllowOriginHeader));
        Assert.Equal(AllowedOrigin, response.Headers.GetValues(AllowOriginHeader).Single());
    }

    [Fact]
    public async Task An_origin_nobody_configured_is_not_allowed()
    {
        using var factory = new ScanApiFactory();
        using var configured = WithAllowedOrigin(factory);
        using var client = configured.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, AnyScanUrl);
        request.Headers.Add("Origin", DisallowedOrigin);

        var response = await client.SendAsync(request);

        Assert.False(response.Headers.Contains(AllowOriginHeader));
    }

    [Fact]
    public async Task No_configuration_allows_no_origin_at_all()
    {
        // The safety property the policy is built around. An unconfigured deployment must fail
        // closed: a missing setting produces a UI that visibly cannot reach the API, not an API
        // quietly reachable from every origin on the internet. Pinned here because the
        // convenient alternative — falling back to a wildcard — leaves nothing failing to show
        // it happened.
        using var factory = new ScanApiFactory();
        using var client = factory.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, AnyScanUrl);
        request.Headers.Add("Origin", AllowedOrigin);

        var response = await client.SendAsync(request);

        Assert.False(response.Headers.Contains(AllowOriginHeader));
    }

    [Fact]
    public async Task A_preflight_is_answered_before_authentication()
    {
        // The ordering of UseCors against UseAuthentication, asserted rather than assumed.
        //
        // A preflight is issued by the browser itself and cannot carry the SPA's bearer token,
        // so if authentication runs first this OPTIONS request comes back 401 and the browser
        // never sends the real call — the whole API appears dead to the dashboard while its
        // logs show nothing but unauthenticated requests.
        using var factory = new ScanApiFactory();
        using var configured = WithAllowedOrigin(factory);
        using var client = configured.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Options, AnyScanUrl);
        request.Headers.Add("Origin", AllowedOrigin);
        request.Headers.Add("Access-Control-Request-Method", "GET");
        request.Headers.Add("Access-Control-Request-Headers", "Authorization");

        var response = await client.SendAsync(request);

        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(AllowedOrigin, response.Headers.GetValues(AllowOriginHeader).Single());
    }
}

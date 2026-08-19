using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using SentinelAI.Api;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Retention;

/// <summary>
/// SEC-35, encryption in transit: the API refuses to serve plain HTTP when transport security
/// is required.
/// </summary>
/// <remarks>
/// <para>
/// This is testable at all because the middleware is behind
/// <see cref="DependencyInjection.RequireHttpsKey"/> rather than an <c>IsDevelopment()</c>
/// guard. The guard is the usual way to keep the redirect out of a test suite that speaks
/// HTTP — and it also makes the redirect impossible to assert, so transport security ends up
/// shipped and unverified. A setting lets the suite keep its HTTP default and still prove the
/// production behaviour.
/// </para>
/// <para>
/// What is at stake is not abstract: a scan bundle carries a customer's infrastructure
/// configuration, and every request to this API carries a bearer token.
/// </para>
/// </remarks>
public class TransportSecurityTests
{
    /// <summary>
    /// The standard test host with transport security switched on, as production has it.
    /// </summary>
    /// <remarks>
    /// Layered with <c>WithWebHostBuilder</c> rather than by subclassing: <c>ScanApiFactory</c>
    /// is sealed, and this needs one extra configuration value rather than different behaviour.
    /// </remarks>
    private static WebApplicationFactory<Program> HttpsRequired(ScanApiFactory factory) =>
        factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    [DependencyInjection.RequireHttpsKey] = "true",
                })));

    private static readonly WebApplicationFactoryClientOptions NoAutoRedirect = new()
    {
        // The redirect itself is the thing under test, not where it lands.
        AllowAutoRedirect = false,
    };

    private const string AnyScanUrl = "/v1/scans/00000000-0000-0000-0000-000000000000";

    [Fact]
    public async Task A_plain_http_request_is_redirected_to_https_when_required()
    {
        using var factory = new ScanApiFactory();
        using var secured = HttpsRequired(factory);
        using var client = secured.CreateClient(NoAutoRedirect);

        var response = await client.GetAsync(AnyScanUrl);

        Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
        Assert.Equal(Uri.UriSchemeHttps, response.Headers.Location!.Scheme);
    }

    [Fact]
    public async Task The_redirect_happens_before_authentication()
    {
        // An unauthenticated request over HTTP must be redirected, not answered with 401.
        // Answering first would mean the API had processed a request it should not have
        // accepted in the clear — and any token on it was exposed either way.
        using var factory = new ScanApiFactory();
        using var secured = HttpsRequired(factory);
        using var client = secured.CreateClient(NoAutoRedirect);

        var response = await client.GetAsync(AnyScanUrl);

        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
    }

    [Fact]
    public async Task The_test_suite_default_still_serves_http()
    {
        // The other 200-odd integration tests speak HTTP. If this ever starts redirecting they
        // fail en masse for a reason unrelated to what they test, so the default is pinned here
        // deliberately rather than left to be discovered.
        using var factory = new ScanApiFactory();
        using var client = factory.CreateClient(NoAutoRedirect);

        var response = await client.GetAsync(AnyScanUrl);

        Assert.NotEqual(HttpStatusCode.TemporaryRedirect, response.StatusCode);
    }
}

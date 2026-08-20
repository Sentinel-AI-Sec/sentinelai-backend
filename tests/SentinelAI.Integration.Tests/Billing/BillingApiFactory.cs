using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Billing;

/// <summary>
/// <see cref="ScanApiFactory"/> with Stripe configured, a fake gateway, and the ability to sign a
/// webhook the way Stripe does.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="IBillingEventReader"/> is deliberately NOT replaced.</b> Only the outbound
/// gateway is faked. The webhook path runs the real <c>StripeEventReader</c> over a real HMAC
/// computed with the real secret, because the signature check is the only authentication on the
/// only endpoint that can grant a paid plan — a test that swapped it for a fake would be a test
/// that the endpoint works when authentication is disabled.
/// </para>
/// <para>
/// The gateway is faked because the alternative is a network call to Stripe with a real key.
/// Nothing about what this API decides — which price may be sold, which return URL is allowed,
/// what an event means for entitlement — lives on the far side of that call.
/// </para>
/// </remarks>
public sealed class BillingApiFactory : ScanApiFactory
{
    public const string WebhookSecret = "whsec_test_secret_for_signing_only";

    /// <summary>The origin the UI is served from in these tests. Everything else is refused.</summary>
    public const string AllowedOrigin = "https://ui.sentinelai.test";

    public const string TeamMonthlyPriceId = "price_team_monthly_test";
    public const string TeamAnnualPriceId = "price_team_annual_test";

    /// <summary>The gateway every request in this host talks to. Assertable after the fact.</summary>
    public FakeBillingGateway Gateway { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Non-empty so BillingSettings.IsConfigured is true. Never used to reach Stripe:
                // the gateway is replaced below.
                ["Billing:SecretKey"] = "sk_test_not_a_real_key",
                ["Billing:WebhookSecret"] = WebhookSecret,
                ["Billing:FreePlanId"] = "free",
                ["Billing:AllowedReturnOrigins:0"] = AllowedOrigin,

                // The allowlist. A plan absent from here cannot be bought at all, which is what
                // PlanCatalog exists to guarantee — 'enterprise' is deliberately not listed.
                ["Billing:Prices:team:Monthly"] = TeamMonthlyPriceId,
                ["Billing:Prices:team:Annual"] = TeamAnnualPriceId,
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IBillingGateway>();
            services.AddSingleton<IBillingGateway>(Gateway);
        });
    }

    /// <summary>
    /// Signs a payload exactly as Stripe does, so the real reader verifies it.
    /// </summary>
    /// <remarks>
    /// The scheme is an HMAC-SHA256 over <c>"{timestamp}.{payload}"</c>, rendered as
    /// <c>t=&lt;unix&gt;,v1=&lt;lowercase hex&gt;</c>. Reproduced here rather than mocked, so
    /// these tests fail if the verification is ever weakened or removed.
    /// </remarks>
    /// <param name="payload">The exact body that will be sent.</param>
    /// <param name="secret">Signing secret. Pass a wrong one to produce a forged delivery.</param>
    /// <param name="timestamp">
    /// Defaults to now. An old value produces a replay, which the reader's tolerance rejects.
    /// </param>
    public static string Sign(string payload, string? secret = null, DateTimeOffset? timestamp = null)
    {
        var unix = (timestamp ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        var signed = $"{unix.ToString(CultureInfo.InvariantCulture)}.{payload}";

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret ?? WebhookSecret));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(signed));

        return $"t={unix},v1={Convert.ToHexString(hash).ToLowerInvariant()}";
    }
}

/// <summary>
/// Records what the API asked Stripe to do, and answers with plausible ids.
/// </summary>
public sealed class FakeBillingGateway : IBillingGateway
{
    public List<CheckoutSessionRequest> CheckoutRequests { get; } = [];
    public List<string> PortalRequests { get; } = [];
    public List<string> Cancelled { get; } = [];

    /// <summary>Set to make the next call fail the way a declined or unreachable Stripe would.</summary>
    public string? FailWith { get; set; }

    public string CustomerId { get; set; } = "cus_test_default";

    public Task<string> GetOrCreateCustomerAsync(
        Guid tenantId, string email, string? existingCustomerId, CancellationToken ct = default)
    {
        if (FailWith is { } failure) throw new BillingGatewayException(failure);

        // Mirrors the real gateway's contract: an id we already hold is reused, so a second
        // checkout attempt does not produce a second Stripe customer.
        return Task.FromResult(existingCustomerId ?? CustomerId);
    }

    public Task<string> CreateCheckoutSessionAsync(
        CheckoutSessionRequest request, CancellationToken ct = default)
    {
        if (FailWith is { } failure) throw new BillingGatewayException(failure);

        CheckoutRequests.Add(request);
        return Task.FromResult("https://checkout.stripe.test/session/cs_test_123");
    }

    public Task<string> CreatePortalSessionAsync(
        string customerId, string returnUrl, CancellationToken ct = default)
    {
        if (FailWith is { } failure) throw new BillingGatewayException(failure);

        PortalRequests.Add(customerId);
        return Task.FromResult("https://billing.stripe.test/portal/bps_test_123");
    }

    public Task CancelSubscriptionAsync(string subscriptionId, CancellationToken ct = default)
    {
        Cancelled.Add(subscriptionId);
        return Task.CompletedTask;
    }
}

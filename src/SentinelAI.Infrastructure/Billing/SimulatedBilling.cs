using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Enums;

namespace SentinelAI.Infrastructure.Billing;

/// <summary>
/// The signing key and HMAC shared by the simulated gateway and its reader.
/// </summary>
/// <remarks>
/// <para>
/// <b>The simulated path is signed, and that is not ceremony.</b> The one security property this
/// whole feature has is that a plan can only be granted by a delivery whose HMAC verifies. If the
/// offline path skipped the check, the property would be untested precisely where it is cheapest
/// to test, and the first time anybody exercised it for real would be in production against
/// Stripe. So the simulator mints a signature and the reader verifies it, using the same
/// <c>t=…,v1=…</c> shape Stripe uses.
/// </para>
/// <para>
/// The key is fixed and public, which is correct for what it protects: nothing. It stops a
/// hand-typed request forging a promotion inside a demo, and it exercises the verification path.
/// It is not a secret and nothing that matters is defended by it — a deployment that wants real
/// money moved runs the Stripe provider, where the secret comes from Key Vault.
/// </para>
/// </remarks>
public static class SimulatedSignature
{
    /// <summary>Fixed, and not a secret. See the type's remarks.</summary>
    private static readonly byte[] Key = Encoding.UTF8.GetBytes("sentinelai-simulated-billing-v1");

    public const string Header = "Stripe-Signature";

    /// <summary>Signs a payload the way <see cref="Verify"/> expects to find it.</summary>
    public static string Sign(string payload)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return $"t={timestamp},v1={Mac(timestamp, payload)}";
    }

    /// <summary>
    /// Whether this header signs this exact payload.
    /// </summary>
    /// <remarks>
    /// Compared with <see cref="CryptographicOperations.FixedTimeEquals"/> rather than
    /// <c>==</c>. The comparison is not worth attacking here, but the shape of this method is what
    /// somebody will copy when they write the next one, and a timing-unsafe MAC comparison is
    /// exactly the kind of thing that gets copied.
    /// </remarks>
    public static bool Verify(string payload, string? header)
    {
        if (string.IsNullOrWhiteSpace(header)) return false;

        long timestamp = 0;
        string? mac = null;

        foreach (var part in header.Split(',', StringSplitOptions.TrimEntries))
        {
            var split = part.IndexOf('=');
            if (split <= 0) continue;

            var name = part[..split];
            var value = part[(split + 1)..];

            if (name == "t") long.TryParse(value, CultureInfo.InvariantCulture, out timestamp);
            else if (name == "v1") mac = value;
        }

        if (mac is null || timestamp == 0) return false;

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(mac), Encoding.UTF8.GetBytes(Mac(timestamp, payload)));
    }

    private static string Mac(long timestamp, string payload) =>
        Convert.ToHexStringLower(
            HMACSHA256.HashData(Key, Encoding.UTF8.GetBytes($"{timestamp}.{payload}")));

    /// <summary>Signs an opaque token so the simulator's own state cannot be hand-edited.</summary>
    public static string Seal(string json)
    {
        var body = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(json));
        var mac = Convert.ToHexStringLower(HMACSHA256.HashData(Key, Encoding.UTF8.GetBytes(body)));

        return $"{body}.{mac}";
    }

    /// <summary>Opens a token sealed by <see cref="Seal"/>, or null if it was tampered with.</summary>
    public static string? Open(string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;

        var dot = token.LastIndexOf('.');
        if (dot <= 0) return null;

        var body = token[..dot];
        var mac = token[(dot + 1)..];
        var expected = Convert.ToHexStringLower(HMACSHA256.HashData(Key, Encoding.UTF8.GetBytes(body)));

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(mac), Encoding.UTF8.GetBytes(expected)))
        {
            return null;
        }

        try
        {
            return Encoding.UTF8.GetString(Base64Url.DecodeFromChars(body));
        }
        catch (FormatException)
        {
            return null;
        }
    }
}

/// <summary>What a simulated checkout has to remember between the redirect out and back.</summary>
/// <remarks>
/// Carried in a sealed token in the URL rather than in a table. Stripe's own session is state we do
/// not hold either, and a row would need a lifecycle, a cleanup job and a migration to model
/// something that exists for the duration of one redirect.
/// </remarks>
public sealed record SimulatedCheckout
{
    [JsonPropertyName("tenant")] public required Guid TenantId { get; init; }
    [JsonPropertyName("customer")] public required string CustomerId { get; init; }
    [JsonPropertyName("price")] public required string PriceId { get; init; }
    [JsonPropertyName("qty")] public required int Quantity { get; init; }
    [JsonPropertyName("ok")] public required string SuccessUrl { get; init; }
    [JsonPropertyName("no")] public required string CancelUrl { get; init; }
}

/// <summary>
/// <see cref="IBillingGateway"/> with no vendor behind it.
/// </summary>
/// <remarks>
/// <para>
/// Every id it mints is prefixed <c>sim_</c>, so a simulated subscription is recognisable at a
/// glance in the database, in a log line, and in a support conversation. Nothing here ever leaves
/// the deployment.
/// </para>
/// <para>
/// The customer id is derived from the tenant rather than generated, so a tenant that checks out
/// twice keeps one customer — the same invariant the real gateway's <c>existingCustomerId</c>
/// parameter exists to preserve, and worth holding here too so the two behave alike.
/// </para>
/// </remarks>
public sealed class SimulatedBillingGateway(
    IHttpContextAccessor accessor,
    ILogger<SimulatedBillingGateway> logger) : IBillingGateway
{
    /// <summary>Where the simulator's hosted page lives, relative to this API.</summary>
    public const string CheckoutPath = "/v1/billing/simulator/checkout";

    public Task<string> GetOrCreateCustomerAsync(
        Guid tenantId, string email, string? existingCustomerId, CancellationToken ct = default) =>
        Task.FromResult(existingCustomerId is { Length: > 0 }
            ? existingCustomerId
            : $"sim_cus_{tenantId:N}");

    public Task<string> CreateCheckoutSessionAsync(
        CheckoutSessionRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var token = SimulatedSignature.Seal(JsonSerializer.Serialize(new SimulatedCheckout
        {
            TenantId = request.TenantId,
            CustomerId = request.CustomerId,
            PriceId = request.PriceId,
            Quantity = request.Quantity,
            SuccessUrl = request.SuccessUrl,
            CancelUrl = request.CancelUrl,
        }));

        logger.LogWarning(
            "Simulated checkout for tenant {TenantId} on price {PriceId}. No payment will be taken.",
            request.TenantId, request.PriceId);

        return Task.FromResult($"{ApiOrigin()}{CheckoutPath}?session={Uri.EscapeDataString(token)}");
    }

    /// <summary>
    /// There is no portal to open, and saying so is better than a page pretending to be one.
    /// </summary>
    /// <remarks>
    /// Returns the caller's own return URL with a marker on it, so the billing screen lands back
    /// where it started and can explain that card management belongs to the real processor. The
    /// alternative — a fake invoice list — would be the one screen in this product that shows a
    /// customer numbers nobody ever charged.
    /// </remarks>
    public Task<string> CreatePortalSessionAsync(
        string customerId, string returnUrl, CancellationToken ct = default)
    {
        var separator = returnUrl.Contains('?') ? '&' : '?';
        return Task.FromResult($"{returnUrl}{separator}portal=simulated");
    }

    public Task CancelSubscriptionAsync(string subscriptionId, CancellationToken ct = default)
    {
        logger.LogInformation("Simulated subscription {SubscriptionId} cancelled.", subscriptionId);
        return Task.CompletedTask;
    }

    /// <summary>
    /// This API's own origin, so the redirect reaches the simulator and not the SPA.
    /// </summary>
    /// <remarks>
    /// Taken from the live request rather than configured. A relative URL would be resolved by the
    /// browser against the page it is on — the SPA's origin, which in a deployed setup is a
    /// different host that has no <c>/v1</c> to answer with. Falls back to relative when there is
    /// no request, which only happens in a unit test that is not following the redirect anyway.
    /// </remarks>
    private string ApiOrigin()
    {
        var request = accessor.HttpContext?.Request;

        return request is null ? string.Empty : $"{request.Scheme}://{request.Host}";
    }
}

/// <summary>
/// <see cref="IBillingEventReader"/> for deliveries the simulator itself signed.
/// </summary>
/// <remarks>
/// Verifies exactly as the Stripe reader does and refuses on the same terms. The payload shape is
/// this codebase's own <see cref="BillingEvent"/> rather than Stripe's envelope, because there is
/// no vendor here whose schema has to be honoured — only the invariant that an unverified body
/// grants nothing.
/// </remarks>
public sealed class SimulatedBillingEventReader : IBillingEventReader
{
    public BillingEvent? Read(string payload, string? signatureHeader)
    {
        if (!SimulatedSignature.Verify(payload, signatureHeader))
            throw new BillingSignatureException("the simulated webhook signature did not verify");

        try
        {
            return JsonSerializer.Deserialize<SimulatedEvent>(payload)?.ToBillingEvent();
        }
        catch (JsonException ex)
        {
            throw new BillingSignatureException("the simulated webhook body was not readable", ex);
        }
    }

    /// <summary>The wire shape the simulator posts to the webhook.</summary>
    internal sealed record SimulatedEvent
    {
        [JsonPropertyName("id")] public required string EventId { get; init; }
        [JsonPropertyName("occurred_at")] public required DateTime OccurredAt { get; init; }
        [JsonPropertyName("kind")] public required string Kind { get; init; }
        [JsonPropertyName("customer")] public required string CustomerId { get; init; }
        [JsonPropertyName("subscription")] public string? SubscriptionId { get; init; }
        [JsonPropertyName("price")] public string? PriceId { get; init; }
        [JsonPropertyName("status")] public string? Status { get; init; }
        [JsonPropertyName("quantity")] public int Quantity { get; init; } = 1;
        [JsonPropertyName("current_period_end")] public DateTime? CurrentPeriodEnd { get; init; }
        [JsonPropertyName("cancel_at_period_end")] public bool CancelAtPeriodEnd { get; init; }

        public BillingEvent? ToBillingEvent()
        {
            if (!Enum.TryParse<BillingEventKind>(Kind, ignoreCase: true, out var kind))
                return null;

            Enum.TryParse<SubscriptionStatus>(Status, ignoreCase: true, out var status);

            return new BillingEvent
            {
                EventId = EventId,
                OccurredAt = DateTime.SpecifyKind(OccurredAt, DateTimeKind.Utc),
                Kind = kind,
                CustomerId = CustomerId,
                SubscriptionId = SubscriptionId,
                PriceId = PriceId,
                Status = status,
                Quantity = Quantity,
                CurrentPeriodEnd = CurrentPeriodEnd,
                CancelAtPeriodEnd = CancelAtPeriodEnd,
            };
        }
    }
}

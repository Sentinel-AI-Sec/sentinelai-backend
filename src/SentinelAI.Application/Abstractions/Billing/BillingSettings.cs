namespace SentinelAI.Application.Abstractions.Billing;

/// <summary>
/// What this deployment is configured to sell, and where it may send a customer afterwards.
/// </summary>
/// <remarks>
/// Built once from configuration by <c>BillingSettingsLoader</c> in Infrastructure and
/// registered as a singleton, so the handlers above it read a settled answer rather than
/// re-deriving one from <c>IConfiguration</c> — the split <c>EgressPolicy</c> and
/// <c>IOutboundEndpointCatalog</c> already use.
/// </remarks>
public sealed class BillingSettings
{
    /// <summary>The plans and prices this deployment sells.</summary>
    public required PlanCatalog Plans { get; init; }

    /// <summary>
    /// Origins Stripe may return a browser to, as scheme://host[:port] with no trailing slash.
    /// </summary>
    public required IReadOnlyList<string> AllowedReturnOrigins { get; init; }

    /// <summary>
    /// The plan id an account holds when it is paying for nothing. Written onto
    /// <c>Tenant.PlanTier</c> when a subscription lapses, so entitlement never falls back to an
    /// empty string that no feature gate has a case for.
    /// </summary>
    public required string FreePlanId { get; init; }

    /// <summary>
    /// Which processor is wired up. See <see cref="BillingProvider"/>.
    /// </summary>
    public required BillingProvider Provider { get; init; }

    /// <summary>
    /// Whether the simulated processor is in force — no card, no money, real flow.
    /// </summary>
    /// <remarks>
    /// Surfaced on the subscription response so the billing screen can say so. A deployment that
    /// simulates payments and looks identical to one that takes them is a deployment where nobody
    /// can tell whether a customer actually paid.
    /// </remarks>
    public bool IsSimulated => Provider is BillingProvider.Simulated;

    /// <summary>
    /// Whether the endpoints can do anything at all. False means <c>503 Service Unavailable</c>
    /// instead of attempting a call that would fail at the vendor.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Reported rather than thrown at startup on purpose. Billing is optional — the offline
    /// demo, the integration suite and a fresh clone all run without a Stripe account — and an
    /// API that refuses to boot without one would make every other endpoint hostage to a
    /// commercial integration. The billing screens already render an honest "not configured"
    /// state; this is what tells them so.
    /// </para>
    /// <para>
    /// Derived from <see cref="Provider"/> rather than stored beside it. Two settable fields
    /// answering one question is two fields that can disagree, and the disagreements that matter
    /// here are a checkout that 503s on a working account, or one that calls a vendor which is not
    /// there.
    /// </para>
    /// </remarks>
    public bool IsConfigured => Provider is not BillingProvider.None;

    /// <summary>
    /// Whether a URL the browser supplied is one Stripe may be told to return to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The success, cancel and return URLs arrive in the request body, because the origin the
    /// customer started from differs between local development and the deployed app and the
    /// backend cannot know which one this browser is on. That makes them attacker-controlled
    /// input on a redirect, which is the definition of an open redirect: a link to our own API
    /// that bounces the victim to an attacker's page, arriving with our domain in the referrer
    /// and a Stripe checkout in the history — a convincing frame for a credential-harvesting
    /// page.
    /// </para>
    /// <para>
    /// Only the origin is checked, not the whole URL. The path carries the screen state the UI
    /// needs (<c>?checkout=success</c>) and pinning it here would couple this API to the SPA's
    /// routing table, which is a change that would break checkout silently. Restricting the
    /// origin is what closes the vulnerability; the path within our own app is ours either way.
    /// </para>
    /// <para>
    /// An empty allowlist refuses everything, matching how <c>Cors:AllowedOrigins</c> behaves and
    /// for the same reason: a deployment that forgets to configure this gets a checkout that
    /// visibly does not start, not one that will redirect anywhere.
    /// </para>
    /// </remarks>
    public bool IsAllowedReturnUrl(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            return false;

        // GetLeftPart(Authority) renders scheme://host[:port] and omits a default port, which is
        // the same normalization applied to the configured list when it is loaded. Comparing
        // whole URLs, or comparing hosts alone, would either reject a legitimate path or accept
        // http:// where only https:// was configured.
        var origin = uri.GetLeftPart(UriPartial.Authority);

        return AllowedReturnOrigins.Any(allowed =>
            string.Equals(allowed, origin, StringComparison.OrdinalIgnoreCase));
    }
}

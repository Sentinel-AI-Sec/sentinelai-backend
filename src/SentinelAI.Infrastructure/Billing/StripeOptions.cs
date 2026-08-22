using Microsoft.Extensions.Configuration;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Domain.Enums;

namespace SentinelAI.Infrastructure.Billing;

/// <summary>
/// Billing configuration, bound from <c>Billing</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two of these values are secrets and two are not, and the difference is worth knowing.</b>
/// <see cref="SecretKey"/> and <see cref="WebhookSecret"/> are credentials: the first can move
/// money and the second is what proves an incoming webhook really came from Stripe. Neither is
/// ever committed — they arrive from Key Vault, user-secrets or the environment, exactly like
/// <c>Authentication:Jwt:SigningKey</c>. The price ids under <see cref="Prices"/> are public
/// identifiers that appear in any checkout link, so they belong in the committed settings file
/// where a reviewer can see what this deployment sells.
/// </para>
/// <para>
/// There is no publishable key here on purpose. Hosted Checkout does not need one, and adding
/// the field would invite someone to reach for Stripe.js and mount a card field in our own
/// origin — which is the decision that puts this application into PCI scope.
/// </para>
/// </remarks>
public sealed class StripeOptions
{
    public const string SectionName = "Billing";

    /// <summary>
    /// Which processor to use: <c>Stripe</c>, <c>Simulated</c>, or <c>None</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Empty means "decide from the credentials": Stripe when both secrets are present, otherwise
    /// nothing. That default is the safe one — a deployment cannot fall into simulating payments
    /// by forgetting a setting, it has to ask for it by name.
    /// </para>
    /// <para>
    /// <c>Simulated</c> is what the committed <c>appsettings.json</c> asks for, so a fresh clone
    /// demos the full upgrade flow with no Stripe account. The deployed app overrides it with
    /// <c>Billing__Provider=Stripe</c>, exactly as it already overrides
    /// <c>SentinelAI__Models__Provider</c>.
    /// </para>
    /// </remarks>
    public string Provider { get; set; } = string.Empty;

    /// <summary>Stripe secret API key (<c>sk_...</c>). Empty means billing is off.</summary>
    public string SecretKey { get; set; } = string.Empty;

    /// <summary>
    /// The signing secret for this endpoint's webhook (<c>whsec_...</c>). Empty means billing is
    /// off — an unverified webhook is not a degraded mode, it is an open door.
    /// </summary>
    public string WebhookSecret { get; set; } = string.Empty;

    /// <summary>
    /// The tier written onto <c>Tenant.PlanTier</c> when an account pays for nothing.
    /// </summary>
    /// <remarks>
    /// Defaults to <c>free</c> because that is the literal <c>RegisterCommandHandler</c> already
    /// writes for every new tenant, and a lapsed subscription must land back on the same value a
    /// fresh account has — not a synonym for it. The UI's free tier is called <c>developer</c>
    /// in <c>core/billing/plans.ts</c>, and the two never have to agree: a free tenant's
    /// <c>plan_id</c> crosses the wire as null, which the UI resolves to its own free plan.
    /// </remarks>
    public string FreePlanId { get; set; } = "free";

    /// <summary>
    /// Origins Stripe may return a browser to. Falls back to <c>Cors:AllowedOrigins</c>, which is
    /// already the list of places this API believes its UI is served from.
    /// </summary>
    public IList<string> AllowedReturnOrigins { get; } = [];

    /// <summary>
    /// Stripe Price ids, keyed by plan and then cadence — <c>Billing:Prices:team:Monthly</c>.
    /// </summary>
    /// <remarks>
    /// Nested rather than flat (<c>team-monthly</c>) so a deployment can supply it through
    /// environment variables as <c>Billing__Prices__team__Monthly</c>, which is all Azure
    /// Container Apps offers, and so a plan sold at only one cadence simply omits the other key.
    /// </remarks>
    public IDictionary<string, Dictionary<string, string>> Prices { get; } =
        new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Builds the effective <see cref="BillingSettings"/> for a deployment.</summary>
public static class BillingSettingsLoader
{
    /// <summary>Where the CORS origin list lives, reused as the return-URL allowlist default.</summary>
    public const string CorsAllowedOriginsKey = "Cors:AllowedOrigins";

    /// <summary>
    /// Reads <c>Billing</c>, and falls back to the CORS origins for return URLs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Bound by hand with <see cref="ConfigurationBinder.Bind(IConfiguration, object)"/> rather
    /// than <c>Get&lt;T&gt;()</c>, because two of the properties are getter-only collections —
    /// the binder populates those under <c>Bind</c> and silently leaves them empty otherwise,
    /// which is the same trap <c>EgressPolicyLoader</c> documents.
    /// </para>
    /// <para>
    /// <b>Why the CORS list is the default return-URL allowlist.</b> They answer nearly the same
    /// question — "which origins is our UI served from" — and a deployment that has configured
    /// one has already stated the answer. Requiring it twice would mean a working CORS setup and
    /// a checkout that refuses every return URL, which presents as "billing is broken" with
    /// nothing in either config file looking wrong. A deployment that genuinely needs them to
    /// differ sets <c>Billing:AllowedReturnOrigins</c> and this stops reading the CORS list.
    /// </para>
    /// </remarks>
    public static BillingSettings Load(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var options = new StripeOptions();
        configuration.GetSection(StripeOptions.SectionName).Bind(options);

        var provider = ResolveProvider(options);

        var origins = options.AllowedReturnOrigins.Count > 0
            ? options.AllowedReturnOrigins
            : configuration.GetSection(CorsAllowedOriginsKey).Get<string[]>() ?? [];

        return new BillingSettings
        {
            // The simulated processor sells the whole ladder, so the demo can reach every tier.
            // Its "price ids" are synthetic and never leave this deployment; PlanCatalog only ever
            // maps them back to a plan, and the simulated reader is the only thing that mints them.
            Plans = new PlanCatalog(
                provider is BillingProvider.Simulated ? SimulatedPrices() : ReadPrices(options)),
            AllowedReturnOrigins = [.. NormalizeOrigins(origins)],
            FreePlanId = string.IsNullOrWhiteSpace(options.FreePlanId)
                ? "free"
                : options.FreePlanId.Trim(),
            Provider = provider,
        };
    }

    /// <summary>
    /// Flattens the <c>plan -> cadence -> price id</c> tree into the catalog's list.
    /// </summary>
    /// <remarks>
    /// A cadence key that is not a <see cref="BillingPeriod"/> is skipped rather than thrown on.
    /// The failure it represents — a typo like <c>Yearly</c> for <c>Annual</c> — then shows up as
    /// a plan that cannot be bought at that cadence, which the UI already renders honestly, and
    /// not as an API that refuses to start. Nothing about billing should be able to take the rest
    /// of the product down with it.
    /// </remarks>
    private static IEnumerable<PlanPrice> ReadPrices(StripeOptions options)
    {
        foreach (var (planId, cadences) in options.Prices)
        {
            if (cadences is null) continue;

            foreach (var (cadence, priceId) in cadences)
            {
                if (Enum.TryParse<BillingPeriod>(cadence, ignoreCase: true, out var period))
                    yield return new PlanPrice(planId, period, priceId);
            }
        }
    }

    /// <summary>
    /// Reduces each configured value to scheme://host[:port], the form a URL is compared in.
    /// </summary>
    /// <remarks>
    /// An origin copied out of a browser address bar almost always carries a trailing slash, and
    /// one copied out of a CORS config may carry a path. Comparing those ordinally against
    /// <c>Uri.GetLeftPart(Authority)</c> matches nothing, and the failure is indistinguishable
    /// from having configured no origins at all — the same trap <c>AddApiServices</c> trims for
    /// on the CORS list it shares with this one.
    /// </remarks>
    private static IEnumerable<string> NormalizeOrigins(IEnumerable<string> origins) =>
        origins
            .Where(origin => !string.IsNullOrWhiteSpace(origin))
            .Select(origin => Uri.TryCreate(origin.Trim(), UriKind.Absolute, out var uri)
                ? uri.GetLeftPart(UriPartial.Authority)
                : origin.Trim().TrimEnd('/'))
            .Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Which processor the configuration asks for, defaulting to whatever the credentials imply.
    /// </summary>
    /// <remarks>
    /// An unrecognised name is <see cref="BillingProvider.None"/> rather than an exception or a
    /// fallback to Stripe: a typo in this setting must not silently either take the API down at
    /// boot or start charging cards. None is the state the endpoints already handle honestly.
    /// </remarks>
    private static BillingProvider ResolveProvider(StripeOptions options)
    {
        var hasStripeKeys = !string.IsNullOrWhiteSpace(options.SecretKey)
            && !string.IsNullOrWhiteSpace(options.WebhookSecret);

        if (string.IsNullOrWhiteSpace(options.Provider))
            return hasStripeKeys ? BillingProvider.Stripe : BillingProvider.None;

        if (!Enum.TryParse<BillingProvider>(options.Provider.Trim(), ignoreCase: true, out var named))
            return BillingProvider.None;

        // Asking to simulate on a deployment that holds real Stripe credentials is a
        // contradiction, and the only two ways to resolve it silently are both bad: simulate, and
        // paying customers are handed free upgrades; use Stripe, and a staging environment charges
        // real cards. Neither is a guess worth making on someone's behalf, so it fails at boot --
        // the same stance ProviderReadiness takes for the model providers, and for the same reason.
        if (named is BillingProvider.Simulated && hasStripeKeys)
        {
            throw new InvalidOperationException(
                "Billing:Provider is 'Simulated' but Stripe credentials are configured. Set it to "
                + "'Stripe' to take payments, or clear Billing:SecretKey and Billing:WebhookSecret "
                + "to simulate them. Refusing to guess which was meant.");
        }

        // Naming Stripe without the keys to reach it is a misconfiguration, and answering 503 says
        // so far more usefully than an exception from the SDK on a customer's first checkout.
        return named is BillingProvider.Stripe && !hasStripeKeys ? BillingProvider.None : named;
    }

    /// <summary>
    /// Synthetic prices for the simulated processor: every sellable plan, at both cadences.
    /// </summary>
    /// <remarks>
    /// The ids are deliberately shaped as <c>sim_price_*</c> rather than <c>price_*</c>. If one
    /// ever turns up in a log, a support thread or a Stripe dashboard search, it should be
    /// immediately obvious that it never came from Stripe.
    /// </remarks>
    private static IEnumerable<PlanPrice> SimulatedPrices()
    {
        string[] sellable = ["pro", "max", "team"];

        foreach (var plan in sellable)
        {
            foreach (var period in Enum.GetValues<BillingPeriod>())
                yield return new PlanPrice(plan, period, $"sim_price_{plan}_{period}".ToLowerInvariant());
        }
    }
}

using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions.Billing;
using Stripe;
using Stripe.Checkout;

namespace SentinelAI.Infrastructure.Billing;

/// <summary>
/// <see cref="IBillingGateway"/> over Stripe. The only class in the solution that calls Stripe.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every method here is one Stripe call and a translation.</b> No decisions are made in this
/// class: which price may be sold, which return URL is acceptable and what a webhook means for a
/// tenant's entitlement are all settled above it, in handlers that can be tested without a
/// network. What is left is the part that genuinely needs the vendor SDK, and it is small enough
/// to read in one sitting — which is the property that makes "does this application handle card
/// data" answerable by inspection. It does not; it never sees any.
/// </para>
/// <para>
/// <b>The client is constructed once and passed to each service, rather than setting the
/// global.</b> <c>StripeConfiguration.ApiKey</c> is process-wide mutable state: it makes the key
/// in use depend on which service was constructed last, and in a test host running more than one
/// configuration it is a race. An explicit <see cref="StripeClient"/> makes the credential a
/// dependency like any other.
/// </para>
/// </remarks>
public sealed class StripeBillingGateway : IBillingGateway
{
    private readonly StripeClient? _client;

    public StripeBillingGateway(IOptions<StripeOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var secretKey = options.Value.SecretKey;

        // Null rather than a client built on an empty key. A deployment with no Stripe account is
        // a supported state — the offline demo and the integration suite both run in it — and
        // this type still has to be constructible, because TenantPurgeService depends on it for
        // account deletion. Every method below fails fast and says why, instead of sending a
        // request Stripe would answer with an authentication error nobody can act on.
        _client = string.IsNullOrWhiteSpace(secretKey) ? null : new StripeClient(secretKey);
    }

    public async Task<string> GetOrCreateCustomerAsync(
        Guid tenantId, string email, string? existingCustomerId, CancellationToken ct = default)
    {
        var customers = new CustomerService(Require());

        if (!string.IsNullOrWhiteSpace(existingCustomerId))
        {
            try
            {
                var existing = await customers.GetAsync(existingCustomerId, cancellationToken: ct);

                // A customer deleted from the Stripe dashboard still resolves, with Deleted set.
                // Reusing it produces a checkout session that cannot be paid, so fall through and
                // mint a replacement — the caller stores whichever id comes back either way.
                if (existing?.Deleted != true) return existing!.Id;
            }
            catch (StripeException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
            {
                // Same reasoning: the id we remembered is gone, a wiped test account being the
                // usual cause. Creating a replacement beats refusing to sell anything until
                // somebody edits the database by hand.
            }
            catch (StripeException ex)
            {
                throw Wrap(ex);
            }
        }

        try
        {
            var created = await customers.CreateAsync(
                new CustomerCreateOptions
                {
                    Email = email,

                    // So a payment in the Stripe dashboard can be traced back to an account,
                    // which is where every billing support ticket starts. Not load-bearing: the
                    // webhook joins on the customer id, which Stripe sets itself.
                    Metadata = new Dictionary<string, string> { ["tenant_id"] = tenantId.ToString() },
                },

                // Collapses a double-clicked "Upgrade" into one customer. The unique index on
                // Subscription.StripeCustomerId is the durable guarantee; this stops the two
                // requests creating two Stripe customers in the first place, one of which would
                // then be orphaned with no row pointing at it.
                new RequestOptions { IdempotencyKey = $"customer:{tenantId}" },
                ct);

            return created.Id;
        }
        catch (StripeException ex)
        {
            throw Wrap(ex);
        }
    }

    public async Task<string> CreateCheckoutSessionAsync(
        CheckoutSessionRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var sessions = new SessionService(Require());

        try
        {
            var session = await sessions.CreateAsync(
                new SessionCreateOptions
                {
                    Mode = "subscription",
                    Customer = request.CustomerId,
                    LineItems =
                    [
                        new SessionLineItemOptions
                        {
                            Price = request.PriceId,
                            Quantity = request.Quantity,
                        },
                    ],

                    // Stripe substitutes the real id for the placeholder. The UI does not read it
                    // — it re-reads the subscription from our own API instead, because a redirect
                    // is not proof of payment — but it is what lets a support conversation start
                    // from the customer's browser history rather than from a guess.
                    SuccessUrl = AppendSessionId(request.SuccessUrl),
                    CancelUrl = request.CancelUrl,

                    // Promotion codes are entered on Stripe's page, so a discount never has to be
                    // validated, stored or reasoned about here.
                    AllowPromotionCodes = true,

                    Metadata = new Dictionary<string, string>
                    {
                        ["tenant_id"] = request.TenantId.ToString(),
                    },
                },
                cancellationToken: ct);

            return session.Url;
        }
        catch (StripeException ex)
        {
            throw Wrap(ex);
        }
    }

    public async Task<string> CreatePortalSessionAsync(
        string customerId, string returnUrl, CancellationToken ct = default)
    {
        var sessions = new Stripe.BillingPortal.SessionService(Require());

        try
        {
            var session = await sessions.CreateAsync(
                new Stripe.BillingPortal.SessionCreateOptions
                {
                    Customer = customerId,
                    ReturnUrl = returnUrl,
                },
                cancellationToken: ct);

            return session.Url;
        }
        catch (StripeException ex)
        {
            throw Wrap(ex);
        }
    }

    public async Task CancelSubscriptionAsync(string subscriptionId, CancellationToken ct = default)
    {
        var subscriptions = new SubscriptionService(Require());

        try
        {
            await subscriptions.CancelAsync(subscriptionId, cancellationToken: ct);
        }
        catch (StripeException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
        {
            // Already gone: cancelled from the dashboard, or a retry of this same call. The
            // desired end state holds, so this is success. Throwing would make account deletion
            // log an alarming error about a subscription that does not exist.
        }
        catch (StripeException ex)
        {
            throw Wrap(ex);
        }
    }

    /// <summary>
    /// Appends Stripe's checkout-session placeholder, preserving any query the UI already sent.
    /// </summary>
    /// <remarks>
    /// The UI's success URL carries <c>?checkout=success</c>, so concatenating a second <c>?</c>
    /// would produce a URL Angular's router reads as one malformed parameter — and the screen
    /// would lose the state it uses to know it has just come back from Stripe.
    /// </remarks>
    private static string AppendSessionId(string successUrl) =>
        successUrl.Contains('?', StringComparison.Ordinal)
            ? successUrl + "&session_id={CHECKOUT_SESSION_ID}"
            : successUrl + "?session_id={CHECKOUT_SESSION_ID}";

    private StripeClient Require() =>
        _client ?? throw new BillingGatewayException(
            $"No Stripe secret key is configured ({StripeOptions.SectionName}:SecretKey is empty), "
            + "so this deployment cannot talk to Stripe.");

    /// <summary>
    /// Turns a Stripe failure into this codebase's own, so no Stripe type escapes Infrastructure.
    /// </summary>
    /// <remarks>
    /// <c>StripeError.Message</c> is the customer-safe text Stripe intends to be displayed ("your
    /// card was declined") and never card data — Stripe does not put a card number in an error.
    /// Falling back to the exception message keeps transport failures, which carry no StripeError
    /// at all, from being reported as an empty string.
    /// </remarks>
    private static BillingGatewayException Wrap(StripeException ex) =>
        new(ex.StripeError?.Message ?? ex.Message, ex);
}

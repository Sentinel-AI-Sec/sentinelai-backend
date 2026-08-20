using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Billing.Commands.CreateCheckoutSession;

/// <summary>
/// Starts a Stripe Checkout Session for the caller's tenant and returns where to send the browser.
/// </summary>
/// <remarks>
/// <para>
/// <b>The caller names a plan, never a price.</b> An earlier draft of the UI sent the Stripe
/// Price id and expected this endpoint to check it against an allowlist. Passing the plan id
/// instead removes the check rather than performing it: there is no longer an attacker-supplied
/// identifier to validate, because the only thing that can reach Stripe is a price this
/// deployment wrote into its own configuration. Price ids are public — they appear in every
/// payment link — so a body carrying one is an input to be distrusted, and the shortest way to
/// distrust it correctly is not to accept it. It also stops the browser bundle and the server
/// from holding two copies of the same table that must be kept in step by hand.
/// </para>
/// <para>
/// <b>Nothing here grants a plan.</b> This returns a URL. The tenant's entitlement moves only
/// when Stripe's signed <c>checkout.session.completed</c> and <c>customer.subscription.*</c>
/// webhooks arrive — see <c>HandleBillingWebhookCommand</c>. A caller who posts this and then
/// walks away has changed nothing except that their tenant now has a Stripe customer id.
/// </para>
/// </remarks>
/// <param name="PlanId">
/// The plan to buy, as spelled in <c>Billing:Prices</c> and in the UI's
/// <c>core/billing/plans.ts</c> — e.g. <c>team</c>. Matched case-insensitively.
/// </param>
/// <param name="Period">
/// <c>monthly</c> or <c>annual</c>. A string rather than the <c>BillingPeriod</c> enum, because
/// this API registers no <c>JsonStringEnumConverter</c> (see the UI's <c>wire.ts</c>, which
/// depends on that): bound as an enum, <c>"annual"</c> would fail deserialization and surface as
/// an unexplained model-binding error instead of the validator's sentence.
/// </param>
/// <param name="Quantity">
/// Seats. Null means one — the only quantity the UI currently sends.
/// </param>
/// <param name="SuccessUrl">
/// Where Stripe returns the browser after payment. Sent by the client because the origin the
/// customer started from differs between local development and the deployed app, and checked
/// here against <c>BillingSettings.AllowedReturnOrigins</c> — an unchecked return URL on an
/// endpoint anybody can reach is an open redirect.
/// </param>
/// <param name="CancelUrl">Where Stripe returns the browser if they back out. Checked the same way.</param>
public sealed record CreateCheckoutSessionCommand(
    string PlanId,
    string Period,
    int? Quantity,
    string SuccessUrl,
    string CancelUrl) : IRequest<Response>;

using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Application.Features.Billing.Commands.CreateCheckoutSession;
using SentinelAI.Application.Features.Billing.Commands.CreatePortalSession;
using SentinelAI.Application.Features.Billing.Commands.HandleWebhook;
using SentinelAI.Application.Features.Billing.Queries.GetSubscription;
using SentinelAI.Domain.Models;

namespace SentinelAI.Api.Controllers;

/// <summary>
/// Subscriptions, through Stripe Checkout. Four endpoints, and only one of them can grant a plan.
/// </summary>
/// <remarks>
/// <para>
/// <b>The browser never touches a card.</b> It asks this API for a Checkout Session and follows
/// the redirect to a Stripe-hosted page; Stripe redirects it back afterwards. No card number,
/// payment method id or publishable key ever enters our origin, which keeps the application out
/// of PCI scope entirely. The cost is a redirect, which is the right trade for a security
/// product.
/// </para>
/// <para>
/// <b>The redirect back is a cue, not a receipt.</b> Anyone can type the success URL. Only
/// <see cref="Webhook"/> — verified against the deployment's webhook secret — moves a tenant's
/// entitlement, and the UI treats its return from Stripe purely as a reason to re-read
/// <see cref="GetSubscription"/>.
/// </para>
/// <para>
/// Reading a subscription needs only a token; starting or managing one needs the admin role,
/// which each handler re-checks rather than relying on the attribute here. Same rule as
/// <c>ProjectController</c>: buying a plan changes what the tenant is, not what it has looked at.
/// </para>
/// </remarks>
[ApiController]
[Route("v1/billing")]
[Tags("Billing")]
[Authorize]
public class BillingController(ISender sender) : ControllerBase
{
    /// <summary>
    /// The largest webhook body this endpoint will read.
    /// </summary>
    /// <remarks>
    /// Stripe's events are a few kilobytes. This is a bound on the one endpoint in the API that,
    /// by necessity, buffers bytes from an unauthenticated caller <em>before</em> it can verify
    /// anything about them — the signature cannot be checked until the whole body has been read,
    /// so without a limit the check that makes this endpoint safe is also what makes it a place to
    /// post arbitrarily large bodies.
    /// </remarks>
    private const int MaxWebhookBytes = 256 * 1024;

    /// <summary>
    /// What the caller's own organisation is subscribed to.
    /// </summary>
    /// <remarks>
    /// Answers for a tenant that has never paid for anything, rather than <c>404</c> — "no
    /// subscription" is the free tier, which is a plan. Never calls Stripe: the row is a cache of
    /// what Stripe's last signed webhook said, so this screen stays readable during a Stripe
    /// incident and costs nothing to refresh.
    /// </remarks>
    [HttpGet("subscription")]
    public async Task<IActionResult> GetSubscription(CancellationToken ct)
    {
        var response = await sender.Send(new GetSubscriptionQuery(), ct);
        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>
    /// Starts a Checkout Session and returns the Stripe-hosted URL to send the browser to.
    /// </summary>
    /// <remarks>
    /// The body names a plan and a cadence, never a Stripe Price id — see
    /// <see cref="CreateCheckoutSessionCommand"/> for why accepting one would be an
    /// attacker-supplied identifier this endpoint would then have to validate.
    /// </remarks>
    [HttpPost("checkout")]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> CreateCheckout(
        [FromBody] CreateCheckoutSessionCommand command, CancellationToken ct)
    {
        var response = await sender.Send(command, ct);
        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>
    /// Opens Stripe's billing portal — card changes, invoices, cancellation.
    /// </summary>
    [HttpPost("portal")]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> CreatePortal(
        [FromBody] CreatePortalSessionCommand command, CancellationToken ct)
    {
        var response = await sender.Send(command, ct);
        return StatusCode((int)response.StatusCode, response);
    }

    /// <summary>
    /// Stripe calls this. The only endpoint in the API that may grant a paid plan.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>[AllowAnonymous]</c> because Stripe has no bearer token to send.</b> What stands in
    /// for one is an HMAC over the exact request body, keyed with this deployment's webhook
    /// secret — see <c>IBillingEventReader</c>. That check is not optional and has no bypass; an
    /// endpoint that accepted unverified events would let anyone promote any account to any plan.
    /// </para>
    /// <para>
    /// <b>The body is read as raw text, and that is load-bearing.</b> The signature is over the
    /// bytes as sent, so binding to a model and re-serializing — different whitespace, different
    /// key order, different number formatting — would make every delivery fail to verify. The
    /// <c>[FromBody]</c> parameter this endpoint does not have is the bug it is written to avoid.
    /// </para>
    /// </remarks>
    [HttpPost("webhook")]
    [AllowAnonymous]
    [RequestSizeLimit(MaxWebhookBytes)]
    public async Task<IActionResult> Webhook(CancellationToken ct)
    {
        // Left open: disposing this reader would dispose the request body stream, which the
        // framework owns and still has to finish with.
        var payload = await new StreamReader(Request.Body).ReadToEndAsync(ct);

        var response = await sender.Send(
            new HandleBillingWebhookCommand(payload, Request.Headers["Stripe-Signature"]), ct);

        return StatusCode((int)response.StatusCode, response);
    }
}

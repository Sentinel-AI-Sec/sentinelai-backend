using System.Globalization;
using System.Net;
using System.Text.Encodings.Web;
using System.Text.Json;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Application.Abstractions.Billing;
using SentinelAI.Application.Features.Billing.Commands.HandleWebhook;
using SentinelAI.Domain.Enums;
using SentinelAI.Infrastructure.Billing;

namespace SentinelAI.Api.Controllers;

/// <summary>
/// The hosted checkout page for the simulated processor.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists so the offline demo exercises the real sequence, not a shortcut around it.</b>
/// The tempting version of "simulated billing" is an endpoint that writes a plan onto the tenant
/// and returns 200. That would demo nothing: the property worth having is that a browser landing
/// on the success URL proves nothing, and only a signed webhook grants a plan. A stub that skips
/// the webhook removes the very thing the flow is built around.
/// </para>
/// <para>
/// So this does what Stripe does. It renders a page with a Pay button, and paying posts a signed
/// delivery to <c>POST /v1/billing/webhook</c> — the same endpoint, the same handler, the same
/// signature check, the same idempotency ledger — before redirecting the browser back. The only
/// thing missing is a card.
/// </para>
/// <para>
/// <b>Every action here is refused unless the resolved provider is
/// <see cref="BillingProvider.Simulated"/>.</b> Not merely unregistered: a deployment that switches
/// to Stripe must not leave a route behind that mints its own subscription events. The guard is on
/// each action rather than on the class, because attribute routing has no conditional form and a
/// 404 from a route that exists is the honest answer.
/// </para>
/// <para>
/// <c>[AllowAnonymous]</c> for the same reason the webhook is: the browser arrives here by
/// redirect, from a Stripe-hosted page's point of view, carrying no bearer token. What authorises
/// the promotion is the sealed session token in the URL and the signature on the delivery it
/// produces — never the identity of whoever opened the page.
/// </para>
/// </remarks>
[ApiController]
[Route("v1/billing/simulator")]
[Tags("Billing")]
[AllowAnonymous]
public class BillingSimulatorController(ISender sender, BillingSettings settings) : ControllerBase
{
    /// <summary>The fake Stripe-hosted checkout page.</summary>
    [HttpGet("checkout")]
    public IActionResult Checkout([FromQuery] string? session)
    {
        if (!settings.IsSimulated) return NotFound();

        var checkout = Open(session);
        if (checkout is null) return BadRequest("that checkout session is not valid");

        var plan = settings.Plans.FindByPriceId(checkout.PriceId);

        return Content(Page(session!, plan?.PlanId ?? "unknown", plan?.Period, checkout.Quantity), "text/html");
    }

    /// <summary>
    /// Paying: posts a signed delivery to the real webhook, then redirects back.
    /// </summary>
    /// <remarks>
    /// Two events, in the order Stripe sends them — the checkout completing, then the subscription
    /// itself. The second is what actually carries the plan, the status and the period end; the
    /// first carries little worth trusting about state and is sent anyway so the idempotency and
    /// ordering paths see the same traffic shape they will see in production.
    /// </remarks>
    [HttpPost("checkout/complete")]
    public async Task<IActionResult> Complete([FromForm] string? session, CancellationToken ct)
    {
        if (!settings.IsSimulated) return NotFound();

        var checkout = Open(session);
        if (checkout is null) return BadRequest("that checkout session is not valid");

        var now = DateTime.UtcNow;
        var subscriptionId = $"sim_sub_{Guid.CreateVersion7():N}";

        await DeliverAsync(new
        {
            id = $"sim_evt_{Guid.CreateVersion7():N}",
            occurred_at = now,
            kind = nameof(BillingEventKind.CheckoutCompleted),
            customer = checkout.CustomerId,
            subscription = subscriptionId,
        }, ct);

        await DeliverAsync(new
        {
            id = $"sim_evt_{Guid.CreateVersion7():N}",
            // A tick later, so the handler's monotonic ordering check sees this one as the newer of
            // the two rather than as a redelivery to be dropped.
            occurred_at = now.AddSeconds(1),
            kind = nameof(BillingEventKind.SubscriptionChanged),
            customer = checkout.CustomerId,
            subscription = subscriptionId,
            price = checkout.PriceId,
            status = nameof(SubscriptionStatus.Active),
            quantity = checkout.Quantity,
            current_period_end = now.AddDays(30),
            cancel_at_period_end = false,
        }, ct);

        return Redirect(checkout.SuccessUrl);
    }

    /// <summary>Cancelling: no delivery, no change, straight back where they came from.</summary>
    [HttpPost("checkout/cancel")]
    public IActionResult Cancel([FromForm] string? session)
    {
        if (!settings.IsSimulated) return NotFound();

        var checkout = Open(session);

        return checkout is null
            ? BadRequest("that checkout session is not valid")
            : Redirect(checkout.CancelUrl);
    }

    /// <summary>
    /// Posts one event through the webhook handler, signed.
    /// </summary>
    /// <remarks>
    /// Sent through MediatR rather than over HTTP to our own port. A self-request would need the
    /// server's own address, would deadlock a single-threaded test host, and would prove nothing
    /// extra — it is the same handler either way, reached through the same command the controller
    /// action builds.
    /// </remarks>
    private async Task DeliverAsync(object payload, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(payload);

        var response = await sender.Send(
            new HandleBillingWebhookCommand(json, SimulatedSignature.Sign(json)), ct);

        if (response.StatusCode is not HttpStatusCode.OK)
        {
            throw new InvalidOperationException(
                $"the simulated webhook delivery was refused: {response.Message}");
        }
    }

    private static SimulatedCheckout? Open(string? session)
    {
        var json = SimulatedSignature.Open(session);

        return json is null ? null : JsonSerializer.Deserialize<SimulatedCheckout>(json);
    }

    /// <summary>
    /// The page itself. Deliberately plain, and deliberately loud about being a simulation.
    /// </summary>
    /// <remarks>
    /// Not styled to resemble Stripe. A convincing replica of a real payment page is a phishing
    /// template, and the one thing a reader must not come away thinking is that they entered card
    /// details somewhere.
    /// </remarks>
    private static string Page(string session, string planId, BillingPeriod? period, int quantity)
    {
        var encoded = HtmlEncoder.Default.Encode(session);
        var cadence = period?.ToString().ToLowerInvariant() ?? "monthly";
        var seats = quantity.ToString(CultureInfo.InvariantCulture);

        return $$"""
        <!doctype html>
        <html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Simulated checkout</title>
        <style>
          body{background:#131121;color:#e5dff6;font:16px/1.6 system-ui,sans-serif;
               display:grid;place-items:center;min-height:100vh;margin:0;padding:1.5rem}
          .card{background:#1c1a29;border:1px solid #464554;border-radius:16px;
                padding:2rem;max-width:26rem;width:100%}
          h1{font-size:1.25rem;margin:0 0 .25rem}
          .warn{background:rgba(255,194,102,.12);border:1px solid rgba(255,194,102,.5);
                color:#ffc266;border-radius:10px;padding:.75rem 1rem;font-size:.85rem;margin:1rem 0}
          dl{display:grid;grid-template-columns:auto 1fr;gap:.35rem 1rem;font-size:.9rem;margin:1rem 0}
          dt{color:#908fa0}dd{margin:0;font-family:ui-monospace,monospace}
          .row{display:flex;gap:.6rem;margin-top:1.25rem}
          button{flex:1;padding:.7rem 1rem;border-radius:10px;font:inherit;font-size:.9rem;cursor:pointer}
          .pay{background:#8083ff;color:#1000a9;border:0;font-weight:600}
          .cancel{background:transparent;color:#c7c4d7;border:1px solid #464554}
        </style></head><body>
        <main class="card">
          <h1>Simulated checkout</h1>
          <p style="margin:0;color:#908fa0;font-size:.9rem">SentinelAI</p>
          <div class="warn"><strong>No payment will be taken.</strong> This deployment has no
          payment processor configured. Continuing signs a webhook to this API exactly as a real
          one would, so the upgrade flow can be demonstrated end to end.</div>
          <dl>
            <dt>Plan</dt><dd>{{planId}}</dd>
            <dt>Billed</dt><dd>{{cadence}}</dd>
            <dt>Seats</dt><dd>{{seats}}</dd>
          </dl>
          <div class="row">
            <form method="post" action="/v1/billing/simulator/checkout/cancel" style="flex:1">
              <input type="hidden" name="session" value="{{encoded}}">
              <button class="cancel" type="submit">Cancel</button>
            </form>
            <form method="post" action="/v1/billing/simulator/checkout/complete" style="flex:1">
              <input type="hidden" name="session" value="{{encoded}}">
              <button class="pay" type="submit">Complete simulated payment</button>
            </form>
          </div>
        </main></body></html>
        """;
    }
}

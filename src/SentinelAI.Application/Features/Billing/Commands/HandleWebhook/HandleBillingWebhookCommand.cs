using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Billing.Commands.HandleWebhook;

/// <summary>
/// Applies one Stripe webhook delivery to the subscription it concerns.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the only thing in the system that may grant a paid plan.</b> Every other billing
/// endpoint hands out a URL or reads a row. A redirect back from Checkout proves nothing — anyone
/// can type the success URL — so the entitlement moves here, on an event whose HMAC was verified
/// against a secret only Stripe and this deployment hold.
/// </para>
/// <para>
/// Carries the raw body as a string, not a bound model. The signature is over the bytes as sent;
/// letting the framework deserialize and re-serialize them would change whitespace and key order
/// and no delivery would ever verify.
/// </para>
/// </remarks>
/// <param name="Payload">The request body, exactly as received.</param>
/// <param name="SignatureHeader">The <c>Stripe-Signature</c> header.</param>
public sealed record HandleBillingWebhookCommand(string Payload, string? SignatureHeader)
    : IRequest<Response>;

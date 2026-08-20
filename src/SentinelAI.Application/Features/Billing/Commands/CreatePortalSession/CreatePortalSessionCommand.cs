using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Billing.Commands.CreatePortalSession;

/// <summary>
/// Opens Stripe's billing portal for the caller's tenant — card changes, invoices, cancellation.
/// </summary>
/// <remarks>
/// <para>
/// <b>Not rebuilt in this application, deliberately.</b> Invoice history, card management and
/// cancellation are the screens where a homegrown version carries the most risk and the least
/// value: they are where card data would have to be handled, where tax and localisation live,
/// and where getting it wrong means either charging someone who cancelled or losing an audit
/// trail. Stripe's portal is already compliant and localised, and handing off means cancellation
/// arrives back here as a signed webhook rather than as a button this codebase has to be trusted
/// to honour.
/// </para>
/// <para>
/// Takes only a return URL because there is nothing else to say — which customer's portal to open
/// comes from the verified token, and the plan comes from Stripe.
/// </para>
/// </remarks>
/// <param name="ReturnUrl">
/// Where the portal's "back" link sends the browser. Checked against
/// <c>BillingSettings.AllowedReturnOrigins</c> for the same reason the checkout URLs are.
/// </param>
public sealed record CreatePortalSessionCommand(string ReturnUrl) : IRequest<Response>;

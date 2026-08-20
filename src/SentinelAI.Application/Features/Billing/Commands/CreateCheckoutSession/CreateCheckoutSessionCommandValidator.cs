using FluentValidation;
using SentinelAI.Domain.Enums;

namespace SentinelAI.Application.Features.Billing.Commands.CreateCheckoutSession;

/// <summary>
/// Shape checks only. Whether this deployment sells the plan, and whether the return URLs point
/// somewhere it is willing to redirect to, are answered by the handler against configuration.
/// </summary>
public sealed class CreateCheckoutSessionCommandValidator
    : AbstractValidator<CreateCheckoutSessionCommand>
{
    /// <summary>
    /// A hard ceiling on seats, so a typo cannot start a five-figure checkout.
    /// </summary>
    /// <remarks>
    /// The number is arbitrary and that is fine: nothing legitimate in this product is bought a
    /// thousand seats at a time, and an organisation that needs more is on the Enterprise tier,
    /// which is sold by conversation rather than through this endpoint. Without a bound, a
    /// mistyped quantity reaches Stripe and produces a real payment page for a real amount.
    /// </remarks>
    public const int MaxQuantity = 999;

    public CreateCheckoutSessionCommandValidator()
    {
        RuleFor(x => x.PlanId)
            .NotEmpty()
            .MaximumLength(100);

        RuleFor(x => x.Period)
            .NotEmpty()
            .Must(period => Enum.TryParse<BillingPeriod>(period, ignoreCase: true, out _))
            .WithMessage("period must be 'monthly' or 'annual'");

        // Optional, but not "optional and then anything". A caller who sends the field is stating
        // a seat count, and zero or a negative is not one — silently substituting 1 would charge
        // for something nobody asked for.
        RuleFor(x => x.Quantity)
            .InclusiveBetween(1, MaxQuantity)
            .When(x => x.Quantity is not null);

        RuleFor(x => x.SuccessUrl)
            .NotEmpty()
            .Must(BeAnAbsoluteHttpUrl)
            .WithMessage("successUrl must be an absolute http(s) URL");

        RuleFor(x => x.CancelUrl)
            .NotEmpty()
            .Must(BeAnAbsoluteHttpUrl)
            .WithMessage("cancelUrl must be an absolute http(s) URL");
    }

    /// <summary>
    /// Absolute and http(s), which is the precondition for checking an origin at all.
    /// </summary>
    /// <remarks>
    /// Not the allowlist check — that is the handler's, against configuration this validator
    /// cannot see. This only rules out the inputs for which "which origin is this" has no answer:
    /// a relative path, and schemes like <c>javascript:</c> that would be a redirect target of a
    /// very different kind.
    /// </remarks>
    private static bool BeAnAbsoluteHttpUrl(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
}

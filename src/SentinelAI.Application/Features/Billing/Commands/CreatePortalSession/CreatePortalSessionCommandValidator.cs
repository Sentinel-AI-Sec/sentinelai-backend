using FluentValidation;

namespace SentinelAI.Application.Features.Billing.Commands.CreatePortalSession;

/// <summary>
/// Shape only. Whether the origin is one this deployment will return to is the handler's
/// question, against configuration this validator cannot see.
/// </summary>
public sealed class CreatePortalSessionCommandValidator
    : AbstractValidator<CreatePortalSessionCommand>
{
    public CreatePortalSessionCommandValidator()
    {
        RuleFor(x => x.ReturnUrl)
            .NotEmpty()
            .Must(value =>
                Uri.TryCreate(value, UriKind.Absolute, out var uri)
                && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
            .WithMessage("returnUrl must be an absolute http(s) URL");
    }
}

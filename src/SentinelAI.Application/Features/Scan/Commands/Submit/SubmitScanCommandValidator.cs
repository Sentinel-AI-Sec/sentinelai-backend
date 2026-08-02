using FluentValidation;

namespace SentinelAI.Application.Features.Scan.Commands.Submit;

public sealed class SubmitScanCommandValidator : AbstractValidator<SubmitScanCommand>
{
    public SubmitScanCommandValidator()
    {
        RuleFor(x => x.MetadataJson)
            .NotEmpty().WithMessage("the multipart 'metadata' part is required");
 
        RuleFor(x => x.Bundle)
            .NotNull().WithMessage("the multipart 'bundle' part is required");
    }
}
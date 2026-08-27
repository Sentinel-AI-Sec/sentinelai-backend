using FluentValidation;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Account.Commands.ChangeMemberRole;

/// <summary>
/// Shape checks only. Whether the target exists, belongs to this tenant, or is the caller
/// themselves are questions no validator can answer — they need the database and the token, and
/// they live in the handler.
/// </summary>
public sealed class ChangeMemberRoleCommandValidator : AbstractValidator<ChangeMemberRoleCommand>
{
    public ChangeMemberRoleCommandValidator()
    {
        RuleFor(x => x.UserId)
            .NotEmpty()
            .WithMessage("a target user id is required");

        // Checked against the canonical list rather than a hand-written set of three, so a role
        // added to Roles.All is assignable without a second edit here. Case-sensitive on
        // purpose: the value is written verbatim into a JWT claim and compared verbatim by
        // [Authorize(Roles = ...)], so "Admin" stored today is a role that authorises nothing
        // tomorrow. Refusing it is the only answer that cannot silently create a dead account.
        RuleFor(x => x.Role)
            .NotEmpty()
            .Must(Roles.All.Contains!)
            .WithMessage($"role must be one of: {string.Join(", ", Roles.All)}");
    }
}

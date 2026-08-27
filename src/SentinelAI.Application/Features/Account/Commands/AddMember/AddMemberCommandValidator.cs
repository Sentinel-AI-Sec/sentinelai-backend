using FluentValidation;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Account.Commands.AddMember;

/// <summary>
/// Shape checks only. Whether the address belongs to a registered account, and what that
/// account's current tenant would be left with, are questions no validator can answer.
/// </summary>
public sealed class AddMemberCommandValidator : AbstractValidator<AddMemberCommand>
{
    public AddMemberCommandValidator()
    {
        // EmailAddress() so a typo is refused as a malformed address rather than reported as
        // "no such account" — the two are different problems and only one is worth retrying
        // with the same string.
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress();

        // Same canonical list as ChangeMemberRoleCommandValidator, and case-sensitive for the
        // same reason: the value is written verbatim into a JWT claim and compared verbatim by
        // [Authorize(Roles = ...)], so "Admin" would be stored as a role that authorises nothing.
        RuleFor(x => x.Role)
            .NotEmpty()
            .Must(Roles.All.Contains!)
            .WithMessage($"role must be one of: {string.Join(", ", Roles.All)}");
    }
}

using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Account.Commands.AddMember;

/// <summary>
/// Moves an existing account into the caller's tenant with the given role (admin only).
/// </summary>
/// <remarks>
/// <para>
/// <b>It adds a person who already has an account; it does not create one.</b> An email that has
/// never registered is refused rather than provisioned, which is what makes this endpoint unable
/// to mint credentials: there is no password in the request and no path here that writes one, so
/// an admin cannot manufacture an account whose password only they know and then sign in as it.
/// Adding someone is therefore always something that happens to an account they do not control.
/// </para>
/// <para>
/// <b>Moving, not copying.</b> <c>User.TenantId</c> is a single foreign key, so an account belongs
/// to exactly one tenant and joining this one means leaving the last. That is why the handler has
/// to reason about what the old tenant is left with — see <c>AddMemberCommandHandler</c>.
/// </para>
/// </remarks>
public sealed record AddMemberCommand : IRequest<Response>
{
    /// <summary>The registered account to bring in. Matched case-insensitively.</summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>The role to give them here: one of <c>Roles.All</c>.</summary>
    public string Role { get; init; } = string.Empty;
}

using System.Text.Json.Serialization;
using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Account.Commands.ChangeMemberRole;

/// <summary>
/// Assigns a role to another member of the caller's tenant (admin only).
/// </summary>
/// <remarks>
/// <para>
/// <b>Unlike <c>DeleteAccountCommand</c>, this one does take a target id</b>, and that is the
/// whole difference between the two operations: deletion can only ever mean "me", whereas
/// granting a role only means anything when it points at someone else. The id being a parameter
/// is what makes the tenant check in the handler load-bearing rather than decorative — see
/// <c>ChangeMemberRoleCommandHandler</c> for why a target outside the caller's tenant answers
/// <c>404</c> and not <c>403</c>.
/// </para>
/// <para>
/// <see cref="UserId"/> is bound from the route rather than the body, so it carries
/// <see cref="JsonIgnoreAttribute"/>: a request that could also name a target in its body would
/// have two sources of truth for the most security-relevant field in it, and model binding would
/// pick one without saying which.
/// </para>
/// </remarks>
public sealed record ChangeMemberRoleCommand : IRequest<Response>
{
    [JsonIgnore]
    public Guid UserId { get; init; }

    /// <summary>The role to assign: one of <c>Roles.All</c>.</summary>
    public string Role { get; init; } = string.Empty;
}

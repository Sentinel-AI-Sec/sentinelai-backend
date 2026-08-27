using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Account;

/// <summary>
/// One member of the caller's tenant, as the members list and the role-change receipt both
/// return them.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="PasswordHash"/> is not here and must never be.</b> Stating that is not
/// paranoia about an obvious mistake: this is the first DTO in the codebase projected from
/// <see cref="User"/>, and <see cref="User"/> carries the hash. A future edit that switches this
/// to returning the entity directly — the shortest possible diff — would publish every member's
/// password hash to every admin in the tenant. The explicit projection in
/// <see cref="From(User)"/> is the thing preventing that, so it is spelled out rather than
/// inferred.
/// </para>
/// <para>
/// <see cref="TenantId"/> is absent for the same reason <c>ProjectResponse</c> omits it: the
/// caller's tenant is a claim on the token they authenticated with, and echoing it back on a row
/// is a field a later bug could populate from the row rather than the token — the shape of a
/// cross-tenant disclosure.
/// </para>
/// <para>
/// <see cref="Role"/> here is the <em>row's</em> role, unlike <c>IdentityResponse.Role</c>, which
/// is read from the verified token. The two answer different questions and the difference is
/// load-bearing: that one reports what the caller's current token will be authorised as, this one
/// reports what the tenant has decided a member is. Immediately after a role change they
/// disagree, on purpose — see <c>ChangeMemberRoleCommandHandler</c>.
/// </para>
/// </remarks>
public sealed record MemberResponse
{
    public required string UserId { get; init; }
    public required string Email { get; init; }

    /// <summary>The role stored on the user row: <c>admin</c>, <c>analyst</c> or <c>viewer</c>.</summary>
    public required string Role { get; init; }

    /// <summary>
    /// What this role grants, from <see cref="RoleScopes.For"/>.
    /// </summary>
    /// <remarks>
    /// Included so an admin choosing a role can see what they are handing over without having to
    /// know the mapping by heart — the difference between <c>analyst</c> and <c>viewer</c> is
    /// entirely <c>scan:write</c>, and a role name alone does not say that.
    /// </remarks>
    public required IReadOnlyList<string> Scopes { get; init; }

    public required bool IsEmailVerified { get; init; }
    public required DateTime CreatedAt { get; init; }

    public static MemberResponse From(User user) => new()
    {
        UserId = user.Id.ToString(),
        Email = user.Email,
        Role = user.Role,
        Scopes = RoleScopes.For(user.Role),
        IsEmailVerified = user.IsEmailVerified,
        CreatedAt = user.CreatedAt,
    };
}

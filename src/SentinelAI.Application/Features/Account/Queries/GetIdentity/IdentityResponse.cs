using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Account.Queries.GetIdentity;

/// <summary>
/// Who the caller is, as the server understands it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is not "already in the token".</b> The console reads its role, tenant and scopes by
/// decoding the JWT client-side. That works for the claims and for nothing else: a JWT carries
/// claim strings, not the tenant's <em>name</em> or the account's email, so a screen built on it
/// can show a GUID and nothing a person recognises. It also means the client parses untrusted
/// base64 before it can render a nav bar, to learn something the API could simply state.
/// </para>
/// <para>
/// <b>Which half comes from where matters, so it is written down.</b> <see cref="TenantName"/>,
/// <see cref="Email"/>, <see cref="PlanTier"/> and <see cref="IsEmailVerified"/> are read from the
/// rows — current facts. <see cref="Role"/> and <see cref="Scopes"/> are read from the verified
/// token, and are deliberately <em>not</em> re-derived from the user row. The question a UI gate
/// asks is "will this request be allowed?", and that is decided by the claims on the bearer token
/// the request will carry. A token issued before a role change still holds the old role until it
/// expires; reporting the row's role there would grey out a button that works, or offer one that
/// 403s. The token is the authority on permission because the token is what gets enforced.
/// </para>
/// <para>
/// <see cref="Scopes"/> is therefore probed against the token rather than mapped from
/// <see cref="RoleScopes"/>, which also makes the answer correct for a machine token: the Action's
/// token carries <c>scan:write</c> and no role at all, and a role-to-scope mapping would report it
/// as holding nothing.
/// </para>
/// </remarks>
public sealed record IdentityResponse
{
    public required string TenantId { get; init; }
    public required string TenantName { get; init; }
    public required string PlanTier { get; init; }

    /// <summary>Null for a machine token — the Action's token names a tenant and no person.</summary>
    public string? UserId { get; init; }

    public string? Email { get; init; }

    /// <summary>The role claim on the verified token: <c>admin</c>, <c>analyst</c> or
    /// <c>viewer</c>. Null for a machine token, which carries scopes and no role.</summary>
    public string? Role { get; init; }

    /// <summary>What this token may actually do. See the remarks on this type.</summary>
    public required IReadOnlyList<string> Scopes { get; init; }

    public bool? IsEmailVerified { get; init; }

    /// <summary>When the account was created, or the tenant when the caller is a machine token.</summary>
    public required DateTime CreatedAt { get; init; }

    public static IdentityResponse From(
        Tenant tenant, User? user, string? role, IReadOnlyList<string> scopes) => new()
    {
        TenantId = tenant.Id.ToString(),
        TenantName = tenant.Name,
        PlanTier = tenant.PlanTier,
        UserId = user?.Id.ToString(),
        Email = user?.Email,
        Role = role,
        Scopes = scopes,
        IsEmailVerified = user?.IsEmailVerified,
        CreatedAt = user?.CreatedAt ?? tenant.CreatedAt,
    };
}

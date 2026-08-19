using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using SentinelAI.Domain.Abstractions.Repositories;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

/// <summary>Resolves tenant, user and scopes from the bearer token's claims.</summary>
/// <remarks>
/// The only place in the codebase that reads claims. Handlers take
/// <see cref="ICallerContext"/> instead, so tenant scoping has exactly one implementation
/// to review rather than one per feature (SEC-26).
/// <para>
/// Reads every claim by its raw, short JWT name ("sub", "role", "scope"/"scp",
/// "tenant_id") — <c>JwtBearerOptions.MapInboundClaims</c> is off
/// (Api/DependencyInjection.cs) specifically so what's issued is what's read, with no
/// silent remap to the legacy long-form <c>ClaimTypes.*</c> URIs in between.
/// </para>
/// </remarks>
public sealed class HttpCallerContext(IHttpContextAccessor accessor) : ICallerContext
{
    private ClaimsPrincipal? User => accessor.HttpContext?.User;

    public bool IsAuthenticated => User?.Identity?.IsAuthenticated ?? false;

    public Guid? TenantId =>
        Guid.TryParse(User?.FindFirst("tenant_id")?.Value, out var id) ? id : null;

    /// <summary>Null for machine tokens — a CI run is not a person.</summary>
    public Guid? UserId =>
        Guid.TryParse(User?.FindFirst("sub")?.Value, out var id) ? id : null;
 
    public bool HasScope(string scope)
    {
        // Accepts both the space-delimited OAuth 'scope' claim and repeated 'scp' claims.
        var claims = User?.FindAll("scope").Concat(User.FindAll("scp")) ?? [];
        return claims.Any(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Contains(scope, StringComparer.Ordinal));
    }

    // Same claim type as JwtBearerOptions.TokenValidationParameters.RoleClaimType
    // (Api/DependencyInjection.cs) — [Authorize(Roles = "...")] reads that claim directly;
    // this just gives handlers the same answer without re-deriving it.
    public string? Role => User?.FindFirst("role")?.Value;
}
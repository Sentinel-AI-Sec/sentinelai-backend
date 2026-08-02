namespace SentinelAI.Domain.Abstractions.Repositories;

/// <summary>
/// Who is calling, resolved from the bearer token by the API layer.
/// </summary>
/// <remarks>
/// Handlers must never reach for HttpContext themselves — tenant scoping is a security
/// control (SEC-26), and it is far easier to prove correct when there is exactly one
/// place that reads claims.
/// </remarks>
public interface ICallerContext
{
    Guid? TenantId { get; }
 
    /// <summary>Null for machine tokens; a user id for JWTs issued to people.</summary>
    Guid? UserId { get; }
 
    bool IsAuthenticated { get; }
 
    bool HasScope(string scope);
}
namespace SentinelAI.Domain.Models;

/// <summary>
/// RBAC roles (SEC-32). Constants, not an enum, for the same reason as
/// <see cref="AuthScopes"/>: a role arrives as an arbitrary string claim in someone else's
/// JWT, and an unrecognized value should simply not match rather than fail to parse.
/// </summary>
/// <remarks>Machine tokens (the GitHub Action) carry no role at all — <c>scan:write</c> is
/// a scope, and a token with no role claim can never satisfy any of these.</remarks>
public static class Roles
{
    public const string Admin = "admin";
    public const string Analyst = "analyst";
    public const string Viewer = "viewer";
}

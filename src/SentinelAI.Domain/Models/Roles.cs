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

    /// <summary>
    /// Every role this build recognises — the set an admin may assign through
    /// <c>PATCH /v1/account/members/{id}</c>.
    /// </summary>
    /// <remarks>
    /// The assignable set and the recognised set are deliberately the same list rather than two
    /// that happen to agree. A role outside it would be stored, would survive a round trip, and
    /// would then resolve to no scopes at all through <see cref="RoleScopes.For"/> — an account
    /// that is silently inert rather than one that was refused. Keeping one list means adding a
    /// role here is the only edit needed to make it assignable, and forgetting to add one makes
    /// it unassignable rather than assignable-but-broken.
    /// </remarks>
    public static readonly IReadOnlyList<string> All = [Admin, Analyst, Viewer];
}

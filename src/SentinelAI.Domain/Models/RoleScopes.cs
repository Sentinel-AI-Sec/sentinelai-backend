namespace SentinelAI.Domain.Models;

/// <summary>
/// Which <see cref="AuthScopes"/> a user of each <see cref="Roles"/> role is issued.
/// </summary>
/// <remarks>
/// <para>
/// The missing half of SEC-32. Roles and scopes both existed and both were enforced —
/// <c>[Authorize(Roles = ...)]</c> on one side, <c>ICallerContext.HasScope</c> on the other —
/// but nothing ever put a <c>scope</c> claim into a token this backend issued. Every scope check
/// therefore failed for every human user, including <c>POST /v1/scans</c>, which no login token
/// could call. The gap survived because the auth tests mint their tokens with a test helper that
/// takes scopes as a parameter, so they exercised the checks without ever exercising the issuer.
/// </para>
/// <para>
/// <b>Roles and scopes are not the same axis, and this does not merge them.</b> A scope says what
/// a token may do; a role says what its holder is. <see cref="Roles.Admin"/> and
/// <see cref="Roles.Analyst"/> get the same scopes on purpose — the difference between them is
/// enforced by role-gated endpoints (bundle purge is admin-only), not by scope.
/// </para>
/// <para>
/// A machine token issued elsewhere (the GitHub Action's) is unaffected: it carries
/// <c>scan:write</c> and no role at all, which is why <c>scan:write</c> is a scope rather than a
/// role in the first place.
/// </para>
/// </remarks>
public static class RoleScopes
{
    /// <summary>Full pipeline access: submit scans, read them, read reports.</summary>
    private static readonly string[] Operator =
        [AuthScopes.ScanWrite, AuthScopes.ScanRead, AuthScopes.ReportRead];

    /// <summary>Read-only. A viewer can see results and never start work.</summary>
    private static readonly string[] ReadOnly =
        [AuthScopes.ScanRead, AuthScopes.ReportRead];

    /// <summary>
    /// What a machine token is issued with — the GitHub Action's, minted by
    /// <c>POST /v1/auth/machine-token</c>.
    /// </summary>
    /// <remarks>
    /// The same three scopes as <see cref="Operator"/>, and a separate member rather than a
    /// reference to it because the two are the same set for different reasons and either could
    /// move without the other. This one is fixed by what the Action does: <c>POST /v1/scans</c>
    /// needs <c>scan:write</c>, the poll step's <c>GET /v1/scans/{id}</c> needs
    /// <c>scan:read</c>, and the PR comment's <c>GET /v1/reports/{id}</c> needs
    /// <c>report:read</c>. Minting <c>scan:write</c> alone yields a run that uploads and then
    /// 403s.
    /// <para>
    /// A machine token carries these and <b>no role claim</b>, which is what keeps it strictly
    /// weaker than the admin token used to mint it — every destructive endpoint is role-gated.
    /// </para>
    /// </remarks>
    public static readonly IReadOnlyList<string> Machine =
        [AuthScopes.ScanWrite, AuthScopes.ScanRead, AuthScopes.ReportRead];

    /// <summary>
    /// The scopes for a role. An unrecognized role gets none — a token that does not say what
    /// its holder is should not be granted anything on the strength of the string being novel.
    /// </summary>
    public static IReadOnlyList<string> For(string? role) => role switch
    {
        Roles.Admin => Operator,
        Roles.Analyst => Operator,
        Roles.Viewer => ReadOnly,
        _ => [],
    };

    /// <summary>
    /// The space-delimited form that goes into a single OAuth <c>scope</c> claim, or null when
    /// the role grants nothing — a claim with an empty value would look like an answer.
    /// </summary>
    public static string? ClaimValue(string? role)
    {
        var scopes = For(role);
        return scopes.Count == 0 ? null : string.Join(' ', scopes);
    }
}

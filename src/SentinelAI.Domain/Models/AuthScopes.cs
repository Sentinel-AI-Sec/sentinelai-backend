namespace SentinelAI.Domain.Models;

/// <summary>
/// Token scopes. The Action's machine token carries <see cref="ScanWrite"/> only.
/// </summary>
/// <remarks>
/// Constants rather than an enum, unlike <c>ScanStatus</c> and <c>ScanStage</c>, and the
/// difference is real: those are closed domains we define and persist, whereas scopes are
/// arbitrary strings arriving inside a JWT issued elsewhere. An enum would mean parsing
/// untrusted claim values into a closed type and deciding what to do when a token carries a
/// scope this build has never heard of — an unknown scope should simply not match, which is
/// exactly what string comparison already does. These are also never stored in a column, so
/// the schema-legibility argument for string-backed enums does not apply.
/// </remarks>
public static class AuthScopes
{
    public const string ScanWrite = "scan:write";
    public const string ScanRead = "scan:read";
    public const string ReportRead = "report:read";

    /// <summary>
    /// Every scope this build enforces.
    /// </summary>
    /// <remarks>
    /// For <c>GET /v1/account</c>, which reports which of these the caller's token actually holds
    /// so a UI can explain a gate rather than just refuse at it. It is the vocabulary this build
    /// checks, not a claim that no other scope string can exist — a token carrying a scope this
    /// build has never heard of still matches nothing, which is the behaviour the remarks above
    /// describe, and such a scope is simply not reportable because nothing here would honour it.
    /// </remarks>
    public static readonly IReadOnlyList<string> All = [ScanWrite, ScanRead, ReportRead];
}
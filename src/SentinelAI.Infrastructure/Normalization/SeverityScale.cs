using System.Globalization;

namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// Collapses every tool's own way of rating seriousness onto the one 0–4 integer scale the
/// <c>Finding</c> contract uses (0 lowest → 4 highest, per docs/Data_Contracts.md).
/// </summary>
/// <remarks>
/// Three dialects arrive: SARIF levels (<c>error</c>/<c>warning</c>/<c>note</c>), plain
/// severity words (<c>CRITICAL</c>/<c>HIGH</c>/…), and CVSS base scores (0–10). They all land
/// here so the mapping is defined once and a new tool cannot quietly invent a sixth bucket.
/// </remarks>
internal static class SeverityScale
{
    /// <summary>SARIF level or severity word → 0–4, or null when the token is unknown/absent.</summary>
    public static int? FromWord(string? word) => word?.Trim().ToLowerInvariant() switch
    {
        "error" or "critical" => 4,
        "warning" or "high" => 3,
        "medium" or "moderate" => 2,
        "note" or "low" => 1,
        "none" or "info" or "informational" => 0,
        _ => null,
    };

    /// <summary>A CVSS base score (0–10) → 0–4, using the standard qualitative bands.</summary>
    public static int FromCvss(double score) => score switch
    {
        >= 9.0 => 4,   // Critical
        >= 7.0 => 3,   // High
        >= 4.0 => 2,   // Medium
        > 0.0 => 1,    // Low
        _ => 0,
    };

    /// <summary>
    /// Best severity from a SARIF result: the explicit level first, then a CVSS
    /// <c>security-severity</c> property, then 0 when neither is present.
    /// </summary>
    public static int FromSarif(string? level, double? securitySeverity)
        => FromWord(level) ?? (securitySeverity is { } cvss ? FromCvss(cvss) : 0);

    /// <summary>Parses a CVSS score written as a string, invariant-culture, or null.</summary>
    public static double? ParseCvss(string? raw)
        => double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : null;
}

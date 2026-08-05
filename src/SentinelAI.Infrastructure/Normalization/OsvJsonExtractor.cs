using System.Text.Json;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// Normalizes OSV-Scanner's <em>native</em> JSON (not its SARIF). OSV reports the dependency
/// layer, and its native output keeps the CVE and GHSA ids — a finding's linking keys — that
/// the SARIF export flattens away. Reading the native shape is the whole reason this extractor
/// is JSON rather than SARIF.
/// </summary>
public sealed class OsvJsonExtractor : IFindingExtractor
{
    public string SourceTool => ScannerNames.Osv;

    public IEnumerable<Finding> Extract(Stream fileContent, Guid tenantId, Guid scanJobId)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(fileContent);
        }
        catch (JsonException ex)
        {
            throw new FindingExtractionException("OSV output is not valid JSON", ex);
        }

        using (doc)
        {
            var findings = new List<Finding>();
            var root = doc.RootElement;

            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("results", out var results) ||
                results.ValueKind != JsonValueKind.Array)
            {
                return findings;
            }

            // results[] -> packages[] -> vulnerabilities[]
            foreach (var result in results.EnumerateArray())
            foreach (var package in EnumerateArray(result, "packages"))
            foreach (var vuln in EnumerateArray(package, "vulnerabilities"))
            {
                findings.Add(new Finding
                {
                    Id = Guid.CreateVersion7(),
                    TenantId = tenantId,
                    ScanJobId = scanJobId,
                    SourceTool = SourceTool,
                    Layer = Layer.Dep,
                    Severity = ResolveSeverity(vuln),
                    CweId = ResolveCwe(vuln),
                    CveId = ResolveVulnId(vuln),
                    // OSV's rule id is the advisory id itself (GHSA-…/OSV-…), which is what a
                    // rule_mappings row for this tool is keyed on. Not persisted (SEC-15).
                    CheckId = GetString(vuln, "id"),
                    // The vulnerable package, not the lock file that lists it — this is what
                    // makes an OSV finding and a Trivy finding about the same package meet on
                    // one graph node at the unify step (SEC-16). Not persisted.
                    Location = ResolvePackage(package),
                    // Built by NodeId at the unify stage, never here (SEC-03).
                    NodeRef = string.Empty,
                    Message = ResolveMessage(vuln),
                    Redacted = false,
                });
            }

            return findings;
        }
    }

    /// <summary>
    /// The package coordinate as <c>name@version</c>, from OSV's <c>package</c> block.
    /// </summary>
    private static string? ResolvePackage(JsonElement packageEntry)
    {
        var package = GetProp(packageEntry, "package");
        var name = GetString(package, "name");
        if (string.IsNullOrWhiteSpace(name)) return null;

        var version = GetString(package, "version");
        return string.IsNullOrWhiteSpace(version) ? name : $"{name}@{version}";
    }

    /// <summary>Prefer a CVE alias (the widely-linkable id); fall back to the native id, e.g. a GHSA.</summary>
    private static string? ResolveVulnId(JsonElement vuln)
    {
        foreach (var alias in EnumerateStrings(vuln, "aliases"))
            if (alias.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
                return alias.ToUpperInvariant();

        return GetString(vuln, "id");
    }

    /// <summary>
    /// OSV's own <c>database_specific.severity</c> word first, then the highest CVSS base score
    /// across the <c>severity</c> array, then 0.
    /// </summary>
    private static int ResolveSeverity(JsonElement vuln)
    {
        var word = GetString(GetProp(vuln, "database_specific"), "severity");
        if (SeverityScale.FromWord(word) is { } fromWord) return fromWord;

        int best = 0;
        foreach (var entry in EnumerateArray(vuln, "severity"))
        {
            if (SeverityScale.ParseCvss(GetString(entry, "score")) is { } cvss)
                best = Math.Max(best, SeverityScale.FromCvss(cvss));
        }

        return best;
    }

    private static string? ResolveCwe(JsonElement vuln)
    {
        var dbSpecific = GetProp(vuln, "database_specific");
        return LinkingKeys.FindCwe(EnumerateStrings(dbSpecific, "cwe_ids"));
    }

    private static string ResolveMessage(JsonElement vuln)
        => GetString(vuln, "summary")
           ?? GetString(vuln, "details")
           ?? GetString(vuln, "id")
           ?? string.Empty;

    private static IEnumerable<JsonElement> EnumerateArray(JsonElement? element, string name)
    {
        if (GetProp(element, name) is { ValueKind: JsonValueKind.Array } array)
            foreach (var item in array.EnumerateArray())
                yield return item;
    }

    private static IEnumerable<string> EnumerateStrings(JsonElement? element, string name)
    {
        foreach (var item in EnumerateArray(element, name))
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { } s)
                yield return s;
    }

    private static JsonElement? GetProp(JsonElement? element, string name)
        => element is { } e && e.ValueKind == JsonValueKind.Object &&
           e.TryGetProperty(name, out var value)
            ? value
            : null;

    private static string? GetString(JsonElement? element, string name)
        => GetProp(element, name) is { ValueKind: JsonValueKind.String } s ? s.GetString() : null;
}

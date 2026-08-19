using System.Text.Json;
using System.Text.RegularExpressions;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// Normalizes OSV-Scanner output, in either shape it emits: its native JSON, or its SARIF.
/// Every OSV finding is a dependency vulnerability, so all of them are <see cref="Layer.Dep"/>.
/// </summary>
/// <remarks>
/// <para>
/// One extractor for both shapes because <c>osv.sarif</c> and <c>osv.json</c> are both JSON and
/// the difference is one property at the root — the same tolerance <see cref="SarifReader"/>
/// applies across SARIF v1 and v2, applied one level up.
/// </para>
/// <para>
/// <b>Why it reads SARIF at all.</b> This extractor originally accepted only the native JSON,
/// on the stated grounds that OSV's SARIF export "drops the CVE/GHSA linking ids". That is true
/// of Dependency-Check, which OSV-Scanner replaced and which is no longer in the toolchain; it
/// is <em>not</em> true of OSV-Scanner, whose SARIF puts the CVE in <c>ruleId</c> and the
/// package coordinate in the message. Meanwhile <c>scripts/run-scanners.sh</c> writes
/// <c>osv.sarif</c> and nothing anywhere writes <c>osv.json</c> — so the whole dependency layer
/// from OSV was being discarded at <c>LogDebug</c> to avoid a data loss that does not occur.
/// </para>
/// <para>
/// The native shape is still preferred where a runner produces it: it states the package name
/// and version as fields rather than inside prose, and carries CWEs in
/// <c>database_specific</c>.
/// </para>
/// </remarks>
public sealed partial class OsvExtractor : IFindingExtractor
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

            if (root.ValueKind != JsonValueKind.Object)
                return findings;

            // A "runs" array is what makes it SARIF; the native shape has "results" at the root.
            if (root.TryGetProperty("runs", out _))
                return FromSarif(root, tenantId, scanJobId);

            if (!root.TryGetProperty("results", out var results) ||
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
    /// The SARIF shape. Every result is one advisory against one package; OSV puts the CVE in
    /// <c>ruleId</c> and states the package in the message as
    /// <c>Package 'Name@Version' is vulnerable to 'CVE-…'</c>.
    /// </summary>
    /// <remarks>
    /// The package is parsed out of the message because it is the only place the SARIF carries
    /// it — the physical location points at the lock file. Without it every OSV finding would
    /// decorate one <c>packages.lock.json</c> node and none would meet Trivy's findings about
    /// the same package (SEC-16). A message OSV words differently yields a null coordinate and
    /// falls back to the lock-file path, which is a coarser node, not a wrong one.
    /// </remarks>
    private List<Finding> FromSarif(JsonElement root, Guid tenantId, Guid scanJobId)
    {
        var findings = new List<Finding>();

        foreach (var result in SarifReader.Read(root))
        {
            var finding = SarifFindings.From(result, SourceTool, Layer.Dep, tenantId, scanJobId);

            // OSV's SARIF ruleId *is* the advisory id, so it serves as both the linking key and
            // the rule id a rule_mappings row would key on.
            finding.CveId ??= result.RuleId;

            if (PackageCoordinate(result.Message) is { } coordinate)
                finding.Location = coordinate;

            findings.Add(finding);
        }

        return findings;
    }

    private static string? PackageCoordinate(string message)
    {
        var match = PackageInMessage().Match(message);
        return match.Success ? match.Groups["pkg"].Value.Trim() : null;
    }

    [GeneratedRegex(@"Package\s+'(?<pkg>[^']+)'\s+is\s+vulnerable", RegexOptions.IgnoreCase)]
    private static partial Regex PackageInMessage();

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

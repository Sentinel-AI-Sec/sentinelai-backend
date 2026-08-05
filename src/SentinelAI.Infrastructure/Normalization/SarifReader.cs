using System.Text.Json;
using SentinelAI.Domain.Abstractions;

namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// A single SARIF result, flattened to just the fields normalization needs, with the tool's
/// rule metadata already resolved in.
/// </summary>
internal sealed record SarifResult(
    string? RuleId,
    string? Level,
    string Message,
    string? CweId,
    string? CveId,
    double? SecuritySeverity);

/// <summary>
/// Reads SARIF into <see cref="SarifResult"/>s, tolerating both v1 and v2. Every scanner that
/// emits SARIF (Roslyn, Trivy, Checkov) shares this reader; only the per-tool layer/id rules
/// differ, and those live in the extractors.
/// </summary>
/// <remarks>
/// It walks the JSON with <see cref="JsonDocument"/> rather than binding to a POCO on purpose:
/// the v1 and v2 shapes disagree in small, load-bearing ways — <c>message</c> is a bare string
/// in v1 and a <c>{ "text": ... }</c> object in v2, rules live under <c>run.rules</c> in v1 and
/// <c>run.tool.driver.rules</c> in v2 — and a defensive walk absorbs those differences where a
/// strict schema would throw on whichever version it was not written against.
/// </remarks>
internal static class SarifReader
{
    public static IReadOnlyList<SarifResult> Read(Stream content)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(content);
        }
        catch (JsonException ex)
        {
            throw new FindingExtractionException("findings file is not valid JSON", ex);
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("runs", out var runs) ||
                runs.ValueKind != JsonValueKind.Array)
            {
                // A SARIF file with no runs is empty, not broken — nothing to normalize.
                return [];
            }

            var results = new List<SarifResult>();
            foreach (var run in runs.EnumerateArray())
            {
                var rules = BuildRuleIndex(run);

                if (!run.TryGetProperty("results", out var runResults) ||
                    runResults.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var result in runResults.EnumerateArray())
                    results.Add(Flatten(result, rules));
            }

            return results;
        }
    }

    /// <summary>
    /// Maps rule id → rule element for the run, covering v2 (<c>tool.driver.rules</c> array) and
    /// v1 (<c>rules</c> as either an array or an id-keyed object). A result carries only its
    /// rule id; the CWE and default level usually live on the rule, so it has to be resolvable.
    /// </summary>
    private static Dictionary<string, JsonElement> BuildRuleIndex(JsonElement run)
    {
        var index = new Dictionary<string, JsonElement>(StringComparer.Ordinal);

        // v2: run.tool.driver.rules (+ any extension.rules)
        if (run.TryGetProperty("tool", out var tool) && tool.ValueKind == JsonValueKind.Object)
        {
            if (tool.TryGetProperty("driver", out var driver))
                IndexRuleArray(driver, index);

            if (tool.TryGetProperty("extensions", out var extensions) &&
                extensions.ValueKind == JsonValueKind.Array)
            {
                foreach (var ext in extensions.EnumerateArray())
                    IndexRuleArray(ext, index);
            }
        }

        // v1: run.rules, an array or an id-keyed object.
        if (run.TryGetProperty("rules", out var v1Rules))
        {
            if (v1Rules.ValueKind == JsonValueKind.Array)
                IndexRules(v1Rules, index);
            else if (v1Rules.ValueKind == JsonValueKind.Object)
                foreach (var member in v1Rules.EnumerateObject())
                    index.TryAdd(member.Name, member.Value);
        }

        return index;
    }

    private static void IndexRuleArray(JsonElement component, Dictionary<string, JsonElement> index)
    {
        if (component.ValueKind == JsonValueKind.Object &&
            component.TryGetProperty("rules", out var rules) &&
            rules.ValueKind == JsonValueKind.Array)
        {
            IndexRules(rules, index);
        }
    }

    private static void IndexRules(JsonElement rules, Dictionary<string, JsonElement> index)
    {
        foreach (var rule in rules.EnumerateArray())
        {
            if (GetString(rule, "id") is { } id)
                index.TryAdd(id, rule);
        }
    }

    private static SarifResult Flatten(JsonElement result, Dictionary<string, JsonElement> rules)
    {
        var ruleId = ResolveRuleId(result);
        var rule = ruleId is not null && rules.TryGetValue(ruleId, out var r) ? r : (JsonElement?)null;

        var level = GetString(result, "level")
                    ?? (rule is { } rr ? GetString(GetProp(rr, "defaultConfiguration"), "level") : null);

        var message = ResolveMessage(result);
        var securitySeverity = SeverityScale.ParseCvss(
            PropertyString(result, "properties", "security-severity")
            ?? (rule is { } r2 ? PropertyString(r2, "properties", "security-severity") : null));

        var cwe = LinkingKeys.FindCwe(CweCandidates(ruleId, result, rule));
        var cve = LinkingKeys.FindCve([ruleId, message, .. TagValues(result), .. RawProperties(result)]);

        return new SarifResult(ruleId, level, message, cwe, cve, securitySeverity);
    }

    /// <summary>v2 puts the id under <c>ruleId</c> or <c>rule.id</c>; v1 uses <c>ruleId</c>.</summary>
    private static string? ResolveRuleId(JsonElement result)
        => GetString(result, "ruleId") ?? GetString(GetProp(result, "rule"), "id");

    /// <summary><c>message</c> is a string in v1 and a <c>{ text | markdown }</c> object in v2.</summary>
    private static string ResolveMessage(JsonElement result)
    {
        if (!result.TryGetProperty("message", out var message))
            return string.Empty;

        return message.ValueKind switch
        {
            JsonValueKind.String => message.GetString() ?? string.Empty,
            JsonValueKind.Object => GetString(message, "text") ?? GetString(message, "markdown") ?? string.Empty,
            _ => string.Empty,
        };
    }

    private static IEnumerable<string?> CweCandidates(string? ruleId, JsonElement result, JsonElement? rule)
    {
        yield return ruleId;

        foreach (var tag in TagValues(result)) yield return tag;
        yield return PropertyString(result, "properties", "cwe");

        if (rule is { } r)
        {
            foreach (var tag in TagValues(r)) yield return tag;
            yield return PropertyString(r, "properties", "cwe");
        }
    }

    /// <summary>Every string in a <c>properties.tags</c> array, if present.</summary>
    private static IEnumerable<string?> TagValues(JsonElement element)
    {
        var properties = GetProp(element, "properties");
        if (properties is null || !properties.Value.TryGetProperty("tags", out var tags) ||
            tags.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var tag in tags.EnumerateArray())
            if (tag.ValueKind == JsonValueKind.String)
                yield return tag.GetString();
    }

    /// <summary>The raw text of the whole <c>properties</c> bag, for a last-resort CVE scan.</summary>
    private static IEnumerable<string?> RawProperties(JsonElement element)
    {
        var properties = GetProp(element, "properties");
        if (properties is { } p) yield return p.GetRawText();
    }

    private static string? PropertyString(JsonElement element, string bag, string name)
        => GetString(GetProp(element, bag), name);

    private static JsonElement? GetProp(JsonElement? element, string name)
        => element is { } e && e.ValueKind == JsonValueKind.Object &&
           e.TryGetProperty(name, out var value)
            ? value
            : null;

    private static string? GetString(JsonElement? element, string name)
        => GetProp(element, name) is { ValueKind: JsonValueKind.String } s ? s.GetString() : null;
}

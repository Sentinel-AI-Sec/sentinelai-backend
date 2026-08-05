using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Normalization;

/// <summary>
/// The rule-mapping step of the Normalize stage (SEC-15): every finding that arrived without a
/// CWE gets one looked up from the tool's rule id, by exact match in <c>rule_mappings</c>.
/// </summary>
/// <remarks>
/// <para>
/// Findings that already carry a CWE are never touched. The scanner that reported the CWE saw
/// the actual result; the table only ever knows the rule in general, so a mapping must not
/// overwrite the more specific answer — and doing so would make the resolved CWE depend on
/// whether a table row happened to exist, which is the opposite of what this step is for.
/// </para>
/// <para>
/// It reads only the abstraction, so the SQL lives in Infrastructure and this stays testable
/// with a dictionary. A lookup failure is not fatal: an unmapped rule leaves the finding exactly
/// as the scanner reported it, which is the same graceful degradation the pipeline applies to an
/// unreadable file.
/// </para>
/// </remarks>
public sealed class RuleMappingResolver(
    IRuleMappingLookup lookup,
    ILogger<RuleMappingResolver> logger)
{
    /// <summary>
    /// Fills in <see cref="Finding.CweId"/> where it is missing, in place, and returns how many
    /// findings were resolved.
    /// </summary>
    public async Task<int> ResolveAsync(IReadOnlyList<Finding> findings, CancellationToken ct = default)
    {
        // Only the gaps, and only the gaps that can be closed: no rule id, nothing to look up.
        var pending = findings
            .Where(f => string.IsNullOrWhiteSpace(f.CweId) && !string.IsNullOrWhiteSpace(f.CheckId))
            .ToList();

        if (pending.Count == 0)
            return 0;

        var keys = pending
            .Select(f => new RuleKey(f.SourceTool, f.CheckId!))
            .Distinct()
            .ToList();

        var resolved = await lookup.ResolveCweAsync(keys, ct);
        if (resolved.Count == 0)
        {
            logger.LogInformation(
                "Rule mapping resolved 0 of {Pending} finding(s) with no CWE ({Keys} distinct rule id(s) unmapped)",
                pending.Count, keys.Count);
            return 0;
        }

        var filled = 0;
        foreach (var finding in pending)
        {
            if (resolved.TryGetValue(new RuleKey(finding.SourceTool, finding.CheckId!), out var cwe))
            {
                finding.CweId = cwe;
                filled++;
            }
        }

        logger.LogInformation(
            "Rule mapping resolved a CWE for {Filled} of {Pending} finding(s) with none, from {Keys} distinct rule id(s)",
            filled, pending.Count, keys.Count);

        return filled;
    }
}

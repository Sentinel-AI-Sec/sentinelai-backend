using Microsoft.EntityFrameworkCore;
using SentinelAI.Application.Abstractions;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// <see cref="IRuleMappingLookup"/> over the <c>rule_mappings</c> SQL table (SEC-15). A plain
/// equality query — the unique index on (<c>source_tool</c>, <c>check_id</c>) is what makes it
/// a lookup rather than a search.
/// </summary>
/// <remarks>
/// Reads are <c>AsNoTracking</c>: these rows are read-only reference data consulted once per
/// scan, so there is nothing to track and no reason to pay for a change-tracking snapshot of
/// them. <c>RuleMapping</c> is not <see cref="Domain.Abstractions.ITenantOwned"/>, so no tenant
/// query filter applies and every tenant sees the same map — intended, per the D2 database
/// design.
/// </remarks>
public sealed class SqlRuleMappingLookup(SentinelDbContext db) : IRuleMappingLookup
{
    public string? ResolveCwe(string sourceTool, string checkId)
        => db.RuleMappings
             .AsNoTracking()
             .Where(r => r.SourceTool == sourceTool && r.CheckId == checkId)
             .Select(r => r.CweId)
             .FirstOrDefault();

    public async Task<IReadOnlyDictionary<RuleKey, string>> ResolveCweAsync(
        IReadOnlyCollection<RuleKey> keys, CancellationToken ct = default)
    {
        var resolved = new Dictionary<RuleKey, string>();
        if (keys.Count == 0)
            return resolved;

        // One query per tool: `source_tool = @tool AND check_id IN (@ids)` is the same exact
        // predicate as the single lookup, asked for a set. Grouping by tool keeps it that way —
        // a flat `IN` over check ids alone would ignore the tool half of the key and could
        // return another scanner's row for a colliding id.
        foreach (var group in keys.GroupBy(k => k.SourceTool, StringComparer.OrdinalIgnoreCase))
        {
            var sourceTool = group.Key;
            var checkIds = group
                .Select(k => k.CheckId)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var rows = await db.RuleMappings
                .AsNoTracking()
                .Where(r => r.SourceTool == sourceTool
                            && checkIds.Contains(r.CheckId)
                            && r.CweId != null)
                .Select(r => new { r.SourceTool, r.CheckId, r.CweId })
                .ToListAsync(ct);

            foreach (var row in rows)
                resolved[new RuleKey(row.SourceTool, row.CheckId)] = row.CweId!;
        }

        return resolved;
    }
}

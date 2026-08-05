namespace SentinelAI.Application.Abstractions;

/// <summary>
/// The identity of one <c>rule_mappings</c> row: a tool plus that tool's own rule id. The same
/// <c>check_id</c> string can mean different things in different scanners, so the tool is part
/// of the key, never assumed.
/// </summary>
/// <remarks>
/// Equality is case-insensitive on both parts deliberately. SQL Server's default collation is
/// case-insensitive, so a row stored as <c>CKV_AWS_20</c> answers a query for <c>ckv_aws_20</c>;
/// if the in-memory key used ordinal equality, that row would come back from the database and
/// then fail to match the finding that asked for it — a silent miss that looks exactly like an
/// absent mapping.
/// </remarks>
public readonly record struct RuleKey(string SourceTool, string CheckId)
{
    public bool Equals(RuleKey other)
        => string.Equals(SourceTool, other.SourceTool, StringComparison.OrdinalIgnoreCase)
           && string.Equals(CheckId, other.CheckId, StringComparison.OrdinalIgnoreCase);

    public override int GetHashCode()
        => HashCode.Combine(
            SourceTool.GetHashCode(StringComparison.OrdinalIgnoreCase),
            CheckId.GetHashCode(StringComparison.OrdinalIgnoreCase));

    public override string ToString() => $"{SourceTool}/{CheckId}";
}

/// <summary>
/// Resolves a missing CWE for a finding from the tool's rule id (SEC-15), by exact lookup in
/// the <c>rule_mappings</c> reference table.
/// </summary>
/// <remarks>
/// <para>
/// This is deliberately the dumbest component in the pipeline: <c>WHERE source_tool = @tool AND
/// check_id = @id</c>. No similarity, no embeddings, no model call. Infrastructure scanners
/// report rules like <c>CKV_AWS_20</c> with no CWE attached, and a finding with no linking key
/// can never be matched to knowledge or joined into a chain — this table is the deterministic
/// way to fill that gap, and its determinism is the point. The moment a mapping becomes a
/// guess, two runs of the same scan can disagree.
/// </para>
/// <para>
/// The table is global reference data, not tenant-scoped, so implementations do not filter by
/// tenant — <c>RuleMapping</c> is intentionally not <c>ITenantOwned</c>.
/// </para>
/// </remarks>
public interface IRuleMappingLookup
{
    /// <summary>
    /// The single exact lookup. Returns the mapped CWE (e.g. <c>CWE-284</c>) or <c>null</c> when
    /// the table has no row for this tool and check id — an unmapped rule is a normal outcome,
    /// not an error.
    /// </summary>
    string? ResolveCwe(string sourceTool, string checkId);

    /// <summary>
    /// The same exact lookup for many keys at once, returning only the keys that resolved to a
    /// non-null CWE.
    /// </summary>
    /// <remarks>
    /// One scan produces hundreds of findings but only a handful of distinct rule ids. Asking
    /// row by row would be a round trip per finding for an answer that repeats; this asks once
    /// per tool and lets <see cref="RuleKey"/> match the rows back. It is the identical
    /// predicate — exact equality on (tool, check_id) — issued in bulk, not a different kind of
    /// search.
    /// </remarks>
    Task<IReadOnlyDictionary<RuleKey, string>> ResolveCweAsync(
        IReadOnlyCollection<RuleKey> keys, CancellationToken ct = default);
}

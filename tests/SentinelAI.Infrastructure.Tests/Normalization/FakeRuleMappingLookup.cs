using SentinelAI.Application.Abstractions;

namespace SentinelAI.Infrastructure.Tests.Normalization;

/// <summary>
/// An in-memory <see cref="IRuleMappingLookup"/> standing in for the <c>rule_mappings</c> table.
/// The behaviour under test is what the resolver <em>does</em> with a mapping, so the table is a
/// dictionary here; that the SQL query finds the right row is <c>SqlRuleMappingLookupTests</c>'
/// job, against a real EF provider.
/// </summary>
/// <remarks>
/// It counts calls so a test can assert the resolver asks once for the whole bundle rather than
/// once per finding — the N+1 this step exists to avoid.
/// </remarks>
internal sealed class FakeRuleMappingLookup : IRuleMappingLookup
{
    private readonly Dictionary<RuleKey, string> _rows = [];

    public int BatchCallCount { get; private set; }

    public IReadOnlyCollection<RuleKey> LastKeys { get; private set; } = [];

    public FakeRuleMappingLookup With(string sourceTool, string checkId, string cwe)
    {
        _rows[new RuleKey(sourceTool, checkId)] = cwe;
        return this;
    }

    public string? ResolveCwe(string sourceTool, string checkId)
        => _rows.TryGetValue(new RuleKey(sourceTool, checkId), out var cwe) ? cwe : null;

    public Task<IReadOnlyDictionary<RuleKey, string>> ResolveCweAsync(
        IReadOnlyCollection<RuleKey> keys, CancellationToken ct = default)
    {
        BatchCallCount++;
        LastKeys = keys;

        var resolved = new Dictionary<RuleKey, string>();
        foreach (var key in keys)
            if (_rows.TryGetValue(key, out var cwe))
                resolved[key] = cwe;

        return Task.FromResult<IReadOnlyDictionary<RuleKey, string>>(resolved);
    }
}

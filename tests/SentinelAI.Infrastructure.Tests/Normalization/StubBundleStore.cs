using System.Text;
using SentinelAI.Domain.Abstractions.Repositories;

namespace SentinelAI.Infrastructure.Tests.Normalization;

/// <summary>
/// A bundle of findings files held in memory, keyed by the path they occupy in the bundle.
/// </summary>
/// <remarks>
/// Keyed by full path rather than by tool, because the path is what the pipeline routes on and
/// several defects have lived in exactly that string — <c>osv.sarif</c> against <c>osv.json</c>,
/// underscores against hyphens. A stub that let a test invent its own names would hide them.
/// </remarks>
internal sealed class StubBundleStore : Dictionary<string, string>, IBundleStore
{
    public Task<IReadOnlyList<StoredBundleFile>> OpenFindingsAsync(string locator, CancellationToken ct)
        => Task.FromResult<IReadOnlyList<StoredBundleFile>>(
            this.Select(kv => new StoredBundleFile(kv.Key, Encoding.UTF8.GetBytes(kv.Value))).ToList());

    public Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct)
        => throw new NotSupportedException();

    public Task<IReadOnlyList<StoredBundleFile>> OpenGraphInputsAsync(string locator, CancellationToken ct)
        => throw new NotSupportedException();

    public Task PurgeAsync(Guid scanJobId, CancellationToken ct) => throw new NotSupportedException();
}

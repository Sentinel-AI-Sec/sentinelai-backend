using SentinelAI.Domain.Abstractions.Repositories;

namespace SentinelAI.Infrastructure.Tests.Security;

/// <summary>
/// A bundle store that serves a fixed set of graph-input artifacts, so the gate's tests read
/// real bytes without a filesystem.
/// </summary>
internal sealed class StubBundleArtifacts : IBundleStore
{
    private readonly List<StoredBundleFile> _artifacts = [];
    private readonly bool _throwOnRead;

    public StubBundleArtifacts(bool throwOnRead = false) => _throwOnRead = throwOnRead;

    public StubBundleArtifacts With(string name, string content)
    {
        _artifacts.Add(new StoredBundleFile(name, System.Text.Encoding.UTF8.GetBytes(content)));
        return this;
    }

    public StubBundleArtifacts WithBytes(string name, byte[] content)
    {
        _artifacts.Add(new StoredBundleFile(name, content));
        return this;
    }

    public Task<IReadOnlyList<StoredBundleFile>> OpenGraphInputsAsync(string locator, CancellationToken ct)
        => _throwOnRead
            ? throw new IOException("the bundle could not be read")
            : Task.FromResult<IReadOnlyList<StoredBundleFile>>(_artifacts);

    public Task<IReadOnlyList<StoredBundleFile>> OpenFindingsAsync(string locator, CancellationToken ct)
        => Task.FromResult<IReadOnlyList<StoredBundleFile>>([]);

    public Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct)
        => Task.FromResult("stub");

    public Task PurgeAsync(Guid scanJobId, CancellationToken ct) => Task.CompletedTask;
}

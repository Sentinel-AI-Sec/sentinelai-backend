using Microsoft.Extensions.Options;
using SentinelAI.Domain.Abstractions.Repositories;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

/// <summary>
/// Returns the configured corpus version until Pipeline A publishes a real one.
/// </summary>
/// <remarks>
/// A placeholder implementation, but not a placeholder field: every audit records the
/// corpus snapshot it retrieved against from day one, so SEC-41 has nothing to retrofit
/// and benchmark runs stay comparable.
/// </remarks>
public sealed class ConfiguredCorpusVersionProvider(IOptions<CorpusOptions> options) : ICorpusVersionProvider
{
    public Task<string> GetCurrentVersionAsync(CancellationToken ct)
        => Task.FromResult(options.Value.Version);
}
 
public sealed class CorpusOptions
{
    public const string SectionName = "Corpus";
    public string Version { get; set; } = "unversioned";
}
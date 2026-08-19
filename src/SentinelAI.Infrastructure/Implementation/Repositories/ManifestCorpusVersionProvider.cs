using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

/// <summary>
/// The corpus version a scan will retrieve against, taken from Pipeline A's manifest (SEC-48).
/// </summary>
/// <remarks>
/// <para>
/// This replaces <see cref="ConfiguredCorpusVersionProvider"/>, whose own summary said what it was
/// waiting for: "Returns the configured corpus version until Pipeline A publishes a real one."
/// It now does. A configured constant answers "what did somebody type into settings"; the manifest
/// answers "what did the ingest actually build", which is the question a reproducible audit needs.
/// </para>
/// <para>
/// <b>Configuration remains the fallback, and stays honest about being one.</b> A deployment with
/// no manifest still stamps something — <c>Corpus:Version</c>, or <c>unversioned</c> — because a
/// job row needs a value and refusing to accept scans over a missing sidecar file would be a
/// worse failure than an imprecise stamp. The log says which of the two answered.
/// </para>
/// </remarks>
public sealed class ManifestCorpusVersionProvider(
    ICorpusManifestSource manifests,
    IOptions<CorpusOptions> options,
    ILogger<ManifestCorpusVersionProvider> logger) : ICorpusVersionProvider
{
    private bool _warned;

    public async Task<string> GetCurrentVersionAsync(CancellationToken ct)
    {
        var manifest = await manifests.GetAsync(ct);

        if (manifest is not null) return manifest.CorpusVersion;

        // Once per process, not once per scan: a missing manifest is a deployment fact, and
        // repeating it per submitted job turns a real signal into noise nobody reads.
        if (!_warned)
        {
            _warned = true;

            logger.LogWarning(
                "No corpus manifest, so scans are stamped with the configured '{Version}' instead "
                + "of a version Pipeline A published. Set Knowledge:Manifest:Path to make the "
                + "stamp reproducible", options.Value.Version);
        }

        return options.Value.Version;
    }
}

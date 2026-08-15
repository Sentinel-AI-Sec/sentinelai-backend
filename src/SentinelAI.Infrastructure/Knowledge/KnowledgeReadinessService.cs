using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;

namespace SentinelAI.Infrastructure.Knowledge;

/// <summary>
/// Wakes the embedding service and proves it is serving the model the corpus was indexed with
/// (SEC-22, and the same-model invariant of <c>PIPELINE_A_CONTEXT.md</c> §5).
/// </summary>
/// <remarks>
/// <para>
/// <b>A background service, not a startup check.</b> <c>ProviderReadiness.Verify</c> is the house
/// pattern for "refuse to boot on a misconfiguration", and it works there because it reads
/// configuration. This has to make a network call to a service that may have been asleep for two
/// days, and waking one takes minutes. Blocking the host on that would mean the API is
/// unreachable — including auth, ingest, and the whole graph stage — because an optional
/// dependency was cold.
/// </para>
/// <para>
/// <b>The two failures are treated differently, because they mean different things.</b>
/// </para>
/// <list type="bullet">
/// <item><description><b>Unreachable</b> — warned about, and the host keeps running. The
/// exact-filter arm needs no embedder and still grounds every finding carrying a clean CVE or
/// CWE. The first semantic query will pay the cold start or fail loudly on its own.</description></item>
/// <item><description><b>Reachable but serving the wrong model</b> — fatal. Every semantic result
/// would be confident and meaningless, which is the one outcome this system exists to avoid
/// producing. Nothing downstream can detect it, so it has to be caught here.</description></item>
/// </list>
/// </remarks>
public sealed class KnowledgeReadinessService(
    IQueryEmbedder embedder,
    IOptions<EmbedderServiceOptions> options,
    ILogger<KnowledgeReadinessService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (embedder is not HttpQueryEmbedder service)
        {
            // NotConfiguredQueryEmbedder, or a test double. Nothing to wake and nothing to prove.
            logger.LogInformation(
                "No embedding service is configured; the semantic and hybrid retrieval arms are "
                + "unavailable and the exact-filter arm is unaffected");

            return;
        }

        if (options.Value.WarmUpOnStartup && !await service.WarmUpAsync(stoppingToken))
        {
            // WarmUpAsync has already logged why. Parity cannot be checked against a service that
            // did not answer, and reporting "parity unknown" adds nothing to "unreachable".
            return;
        }

        // Reached only when the service answered. A mismatch now is a real one.
        await service.VerifyParityAsync(stoppingToken);
    }
}

namespace SentinelAI.Integration.Tests.Knowledge;

/// <summary>
/// A <see cref="FactAttribute"/> that skips unless a live Qdrant endpoint has been named.
/// </summary>
/// <remarks>
/// <para>
/// The SEC-22 adapter's behaviour cannot be asserted without a real index. The one thing that
/// actually matters — that <c>cwe_id=CWE-502</c> plus <c>source=CWE</c> returns the weakness
/// definition rather than the CVEs merely tagged with it — is a property of Qdrant's filtering,
/// so a mock proves nothing about it.
/// </para>
/// <para>
/// Gated rather than always-on because CI has no Qdrant, and gated by an <em>explicit</em>
/// environment variable rather than by probing a port, so a developer who happens to have
/// something else listening on 6334 does not get a confusing failure. Skipped tests are visible
/// in the run summary; a test that silently returns early is not, and this codebase treats
/// silent success as the failure mode worth engineering against.
/// </para>
/// <example>
/// <code>
/// docker run -d --rm -p 6333:6333 -p 6334:6334 qdrant/qdrant
/// SENTINELAI_QDRANT=http://localhost:6334 dotnet test tests/SentinelAI.Integration.Tests
/// </code>
/// </example>
/// </remarks>
public sealed class QdrantFactAttribute : FactAttribute
{
    public const string EndpointVariable = "SENTINELAI_QDRANT";

    /// <summary>Where a local Qdrant listens for gRPC if one is running.</summary>
    private const string DefaultLocal = "http://localhost:6334";

    public QdrantFactAttribute()
    {
        if (Endpoint is null)
        {
            Skip = $"No Qdrant reachable. Run `docker run -p 6334:6334 qdrant/qdrant`, or set "
                 + $"{EndpointVariable}, to run the adapter tests.";
        }
    }

    /// <summary>
    /// The endpoint to use, or null when nothing is reachable.
    /// </summary>
    /// <remarks>
    /// An explicit variable wins; otherwise a local Qdrant is <em>probed for</em> rather than
    /// assumed. Probing means these run whenever a developer has a container up, instead of only
    /// when they remember a variable — and still skip cleanly on a machine with no Qdrant at all.
    /// </remarks>
    public static string? Endpoint { get; } = Resolve();

    private static string? Resolve()
    {
        if (Environment.GetEnvironmentVariable(EndpointVariable) is { Length: > 0 } configured)
            return configured;

        return CanConnect("localhost", 6334) ? DefaultLocal : null;
    }

    /// <summary>A short TCP probe. Runs at discovery, so it must not hang on a dead host.</summary>
    private static bool CanConnect(string host, int port)
    {
        try
        {
            using var client = new System.Net.Sockets.TcpClient();
            return client.ConnectAsync(host, port).Wait(TimeSpan.FromMilliseconds(500))
                && client.Connected;
        }
        catch
        {
            return false;
        }
    }
}

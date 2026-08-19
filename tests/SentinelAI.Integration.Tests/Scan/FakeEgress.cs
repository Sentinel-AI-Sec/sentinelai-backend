using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Security;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// A configured-endpoint catalog with whatever the test wants in it — the input side of
/// SEC-34's egress admission check.
/// </summary>
internal sealed class FakeEndpointCatalog(params OutboundEndpoint[] endpoints) : IOutboundEndpointCatalog
{
    public IReadOnlyList<OutboundEndpoint> Endpoints { get; } = endpoints;

    /// <summary>One configured LLM endpoint, named the way configuration names it.</summary>
    public static FakeEndpointCatalog Llm(string uri) =>
        new(new OutboundEndpoint("SentinelAI:Models:Endpoint", new Uri(uri), EgressPurpose.Llm));
}

internal static class FakeEgress
{
    /// <summary>
    /// The admission check a Scripted deployment gets: the compiled-in vendor allowlist and
    /// no configured endpoints at all. This is what every other test in the suite runs under,
    /// and it passes — which is why the tests that matter configure an endpoint explicitly.
    /// </summary>
    public static EgressAdmission Offline() => For();

    /// <summary>A deployment whose model endpoint is configured to <paramref name="uri"/>.</summary>
    public static EgressAdmission PointedAt(string uri) => For(FakeEndpointCatalog.Llm(uri).Endpoints[0]);

    public static EgressAdmission For(params OutboundEndpoint[] endpoints) =>
        new(EgressPolicy.Default,
            new FakeEndpointCatalog(endpoints),
            NullLogger<EgressAdmission>.Instance);
}

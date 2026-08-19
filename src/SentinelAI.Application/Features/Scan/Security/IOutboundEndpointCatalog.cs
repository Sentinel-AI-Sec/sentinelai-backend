namespace SentinelAI.Application.Features.Scan.Security;

/// <summary>One place this process has been configured to send job content.</summary>
/// <param name="Name">What configured it, e.g. <c>SentinelAI:Models:Agents:Red:Endpoint</c>. Goes in the error.</param>
/// <param name="Uri">The configured absolute URI.</param>
/// <param name="Purpose">Whether it is an inference or a retrieval destination.</param>
public sealed record OutboundEndpoint(string Name, Uri Uri, EgressPurpose Purpose);

/// <summary>
/// Everywhere this process is configured to send job content — the input side of the egress
/// check.
/// </summary>
/// <remarks>
/// A port rather than a concrete read of <c>IConfiguration</c> so the Application layer does
/// not have to know how a provider endpoint is spelled, and so the admission check can be
/// tested against a configuration that points somewhere hostile without a running host.
/// </remarks>
public interface IOutboundEndpointCatalog
{
    /// <summary>
    /// The configured destinations. Empty is the normal answer for the offline
    /// <c>Scripted</c> provider, and for any provider left on its compiled-in vendor default.
    /// </summary>
    IReadOnlyList<OutboundEndpoint> Endpoints { get; }
}

using Microsoft.Extensions.Logging;

namespace SentinelAI.Application.Features.Scan.Security;

/// <summary>
/// Refuses a scan job while this process is configured to send job content somewhere the
/// egress policy does not permit.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this actually buys.</b> The acceptance criterion is "scan job → runs with egress
/// restricted to allowed endpoints". Nothing in a C# process can make that true at the
/// network level. What it can make true is the weaker, checkable statement this class
/// enforces: <em>a job is never accepted into a process whose outbound configuration points
/// off the allowlist</em>. A deployment repointed at a proxy, a debug endpoint, or someone
/// else's gateway stops taking work, at ingest, before a bundle is stored — instead of
/// accepting it, returning 202, and discovering the destination three stages later inside a
/// debate turn, which is where the same class of misconfiguration used to surface (SEC-30's
/// <c>ProviderReadiness</c> exists for that reason, and this is the same idea one step out).
/// </para>
/// <para>
/// <b>Why the check is at ingest and not at the model call.</b> The model boundary would be
/// the stronger place, and it is where a real guard belongs. It is also
/// <c>ChatClientFactory</c>, which builds its clients on <c>System.ClientModel</c>'s
/// pipeline — the transport is a constructor seam owned by another ticket, and putting a
/// half-guard there that only some paths flow through would be worse than an honest one here.
/// This is stated plainly rather than papered over: <b>outbound calls are not intercepted.</b>
/// If configuration passes this check and something later constructs a client by hand, no
/// code in this repository stops it.
/// </para>
/// <para>
/// <b>Why it fails the job rather than the host.</b> Boot-time failure was considered and
/// rejected: a running deployment whose configuration is reloaded is the case that matters,
/// and a check that only ran at startup would report a clean process indefinitely. Refusing
/// at ingest also gives the caller an answer — 503 with the offending host named — instead of
/// a crash loop.
/// </para>
/// </remarks>
public sealed class EgressAdmission(
    IEgressPolicy policy,
    IOutboundEndpointCatalog catalog,
    ILogger<EgressAdmission> logger)
{
    /// <summary>
    /// The reason no job may be accepted right now, or null when egress is confined to the
    /// allowlist.
    /// </summary>
    public string? Describe()
    {
        var endpoints = catalog.Endpoints;

        // The offline provider configures no endpoint at all. That is a pass, and saying so
        // out loud matters: it is the state every test and every fresh clone runs in, so a
        // check that silently succeeded there would be indistinguishable from one that
        // silently succeeded everywhere.
        if (endpoints.Count == 0) return null;

        var denials = endpoints
            .Select(e => (Endpoint: e, Denial: policy.DescribeDenial(e.Uri)))
            .Where(x => x.Denial is not null)
            .ToList();

        if (denials.Count == 0) return null;

        var detail = string.Join("; ", denials.Select(d => $"{d.Endpoint.Name}: {d.Denial}"));

        logger.LogError(
            "Egress policy refused {Count} configured endpoint(s); no scan job will be accepted "
            + "while this stands. {Detail}", denials.Count, detail);

        return "this deployment is configured to send job content outside the egress "
            + $"allowlist, so no scan job can be accepted — {detail}";
    }
}

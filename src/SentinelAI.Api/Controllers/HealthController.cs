using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SentinelAI.Api.Controllers;

/// <summary>
/// Liveness. Answers "is this process up and serving?" and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// There was no health endpoint at all, so the deploy runbook probes <c>/v1/scans</c> and treats
/// the <c>405</c> it gets back as proof of life. That works by accident: it depends on a route
/// keeping a verb it does not implement, it cannot be given to a platform probe that expects a
/// <c>2xx</c>, and it tells a reader nothing about which build answered. The console has the same
/// problem from the other side — with no unauthenticated endpoint to ping, "the API is down" and
/// "your session expired" look identical to a browser, and the second is by far the more common.
/// </para>
/// <para>
/// <b>Anonymous, and deliberately shallow.</b> It touches no database, no bundle store and no
/// model provider. A public endpoint that opens a connection per request is a denial-of-service
/// amplifier — an attacker with no credentials gets to exhaust the connection pool one GET at a
/// time — and against a serverless database on auto-pause it would also wake the instance every
/// time a probe fired. Readiness of a dependency is a question for an authenticated operator
/// endpoint, not this one, and pretending otherwise here would make an outage in the database
/// look like an outage in the API.
/// </para>
/// </remarks>
[ApiController]
[Route("v1/health")]
[Tags("Health")]
[AllowAnonymous]
public class HealthController : ControllerBase
{
    /// <summary>
    /// The build's informational version, resolved once. Falls back to the assembly version, and
    /// then to <c>unknown</c> — a health response that throws is worse than one that admits it
    /// does not know which build it is.
    /// </summary>
    private static readonly string Version =
        typeof(HealthController).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(HealthController).Assembly.GetName().Version?.ToString()
        ?? "unknown";

    /// <summary>Always <c>200</c> while the process is serving requests.</summary>
    [HttpGet]
    public IActionResult Get() => Ok(new HealthResponse
    {
        Status = "ok",
        Version = Version,
        // UTC, and returned so a caller can see whether it is talking to a live process or a
        // cached response sitting in a proxy.
        Time = DateTime.UtcNow,
    });
}

/// <summary>What <c>GET /v1/health</c> answers. Carries nothing an anonymous caller should not
/// see — no configuration, no hostnames, no dependency state.</summary>
public sealed record HealthResponse
{
    public required string Status { get; init; }
    public required string Version { get; init; }
    public required DateTime Time { get; init; }
}

using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// SEC-33's wiring, against the real composition root.
/// </summary>
/// <remarks>
/// The gate's own tests construct it by hand, which proves the logic and nothing about the
/// application. The claim that matters in production is narrower and entirely about
/// registration: <b>the thing you get when you ask for an <see cref="IDebateEngine"/> is the
/// redacting one</b>. If someone later registers the bare engine after this — the ordinary way
/// a decorator quietly disappears — every other SEC-33 test still passes and the guarantee is
/// gone. This is the test that fails instead.
/// </remarks>
public class IngressRedactionWiringTests
{
    [Fact]
    public void The_registered_debate_engine_is_the_redacting_one()
    {
        using var factory = new ScanApiFactory();
        using var scope = factory.Services.CreateScope();

        var engine = scope.ServiceProvider.GetRequiredService<IDebateEngine>();

        // Somewhere in the chain, not outermost. SEC-50 legitimately wraps this one in its edge
        // checker, and asserting the exact outermost type made that correct change a red build
        // while the guarantee it was protecting still held. What SEC-33 needs is that a brief
        // cannot reach a provider without passing the scan.
        Assert.True(
            engine.Wraps<RedactingDebateEngine>(),
            "the resolved IDebateEngine does not redact anywhere in its chain: "
            + string.Join(" -> ", engine.Unwrap().Select(e => e.GetType().Name)));
    }

    /// <summary>
    /// The chain is exactly what the composition root builds, in order.
    /// </summary>
    /// <remarks>
    /// The test above deliberately does not care about order, so on its own it would still pass if
    /// a decorator were dropped and another added. This one pins the actual shape, so a change to
    /// the chain is a decision someone makes here rather than something that drifts.
    /// </remarks>
    [Fact]
    public void The_debate_engine_chain_is_edge_integrity_over_redaction_over_the_real_engine()
    {
        using var factory = new ScanApiFactory();
        using var scope = factory.Services.CreateScope();

        var chain = scope.ServiceProvider.GetRequiredService<IDebateEngine>()
            .Unwrap().Select(e => e.GetType().Name).ToList();

        Assert.Equal(
            ["EdgeIntegrityDebateEngine", "RedactingDebateEngine", "DebateEngine"],
            chain);
    }

    [Fact]
    public void The_gate_and_its_scanner_resolve_from_the_container()
    {
        using var factory = new ScanApiFactory();
        using var scope = factory.Services.CreateScope();

        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ISecretScanner>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IngressRedactionGate>());
    }
}

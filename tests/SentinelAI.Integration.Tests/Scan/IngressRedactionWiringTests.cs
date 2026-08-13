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

        Assert.IsType<RedactingDebateEngine>(engine);
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

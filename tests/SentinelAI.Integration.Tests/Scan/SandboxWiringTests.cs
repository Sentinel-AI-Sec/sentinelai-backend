using MediatR;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Features.Scan.Commands.Submit;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Domain.Premitives;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// SEC-34's wiring, against the real composition root.
/// </summary>
/// <remarks>
/// The policy tests construct everything by hand, which proves the rules and nothing about
/// the application. What matters in production is that the submit handler the container
/// builds has the check in it — a registration missing from <c>AddInfrastructureServices</c>
/// would leave every policy test green and the ingest path unguarded, which is the exact
/// shape of the "registered but called by nothing" defects this project keeps finding.
/// </remarks>
public class SandboxWiringTests
{
    [Fact]
    public void The_egress_check_and_its_two_ports_resolve_from_the_container()
    {
        using var factory = new ScanApiFactory();
        using var scope = factory.Services.CreateScope();

        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IEgressPolicy>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IOutboundEndpointCatalog>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<EgressAdmission>());
    }

    [Fact]
    public void The_submit_handler_the_container_builds_carries_the_egress_check()
    {
        // Resolving the handler itself is the assertion: its constructor requires an
        // EgressAdmission, so a container that cannot supply one throws here rather than at
        // the first upload.
        using var factory = new ScanApiFactory();
        using var scope = factory.Services.CreateScope();

        var handler = scope.ServiceProvider
            .GetRequiredService<IRequestHandler<SubmitScanCommand, Response>>();

        Assert.IsType<SubmitScanCommandHandler>(handler);
    }

    [Fact]
    public void The_default_deployment_admits_jobs()
    {
        // Scripted provider, no endpoints configured: the check must pass. A guard that
        // refused the default configuration would be switched off within a day.
        using var factory = new ScanApiFactory();
        using var scope = factory.Services.CreateScope();

        Assert.Null(scope.ServiceProvider.GetRequiredService<EgressAdmission>().Describe());
    }
}

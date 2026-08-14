using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Commands.Submit;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Implementation.Repositories;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// SEC-34's two acceptance boxes, on the path that actually accepts a job: the real
/// <see cref="TarGzBundleInspector"/> and the real <see cref="SubmitScanCommandHandler"/>,
/// with fakes only for storage, persistence and auth.
/// </summary>
/// <remarks>
/// <para>
/// <b>Box 2 — no application source to process.</b> The interesting test here is
/// <see cref="A_bundle_the_ingest_denylist_waves_through_is_still_refused"/>. It uses a
/// <c>.js</c> file, which the inspector's source denylist does not list, so the bundle is
/// <em>accepted by every guard that runs before the content policy</em> — the assertion is
/// demonstrably load-bearing rather than a second opinion on a decision already made.
/// </para>
/// <para>
/// <b>Box 1 — restricted egress.</b> What is proven below is that a deployment configured to
/// send job content off the allowlist does not accept jobs. That is a configuration
/// assertion, not a network sandbox; no test here intercepts an outbound call, because
/// nothing in this repository does.
/// </para>
/// </remarks>
public class SandboxedProcessingTests
{
    private static readonly Guid TenantId = Guid.NewGuid();
    private static readonly Guid ProjectId = Guid.NewGuid();

    private static (SubmitScanCommandHandler Handler, FakeUnitOfWork UnitOfWork, FakeBundleStore Store)
        CreateHandler(Application.Features.Scan.Security.EgressAdmission? egress = null)
    {
        var project = new Project { Id = ProjectId, TenantId = TenantId };
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository { Project = project });
        var store = new FakeBundleStore();
        var inspector = new TarGzBundleInspector(NullLogger<TarGzBundleInspector>.Instance);

        var handler = new SubmitScanCommandHandler(
            unitOfWork, inspector, store,
            new FakeCorpusVersionProvider(),
            new FakeCallerContext { TenantId = TenantId },
            egress ?? FakeEgress.Offline());

        return (handler, unitOfWork, store);
    }

    private static string MetadataFor(Guid projectId) => $$"""
        {
          "project_id": "{{projectId}}",
          "commit_sha": "abc123",
          "artifacts": [{ "kind": "sarif", "tool": "osv-scanner", "filename": "findings/osv.sarif" }]
        }
        """;

    private static MemoryStream BundleWith(params (string Name, string Content)[] extra)
    {
        var files = new Dictionary<string, string>
        {
            ["metadata.json"] = MetadataFor(ProjectId),
            ["scanner-versions.json"] = "{}",
            ["findings/osv.sarif"] = "{}",
            ["graph-inputs/infra/main.tf"] = "resource \"aws_s3_bucket\" \"x\" {}",
            ["graph-inputs/Dockerfile"] = "FROM mcr.microsoft.com/dotnet/aspnet:8.0\n",
            ["graph-inputs/src/OrderApp/packages.lock.json"] = "{\"version\":1}",
        };

        foreach (var (name, content) in extra) files[name] = content;
        return TarGzTestHelper.Build(files);
    }

    // ---- box 2: no application source is present to process ------------------------------

    [Fact]
    public async Task A_bundle_of_exactly_the_collectors_artifacts_is_accepted()
    {
        var (handler, unitOfWork, _) = CreateHandler();
        await using var bundle = BundleWith();

        var response = await handler.Handle(
            new SubmitScanCommand(MetadataFor(ProjectId), bundle), CancellationToken.None);

        Assert.True(response.IsSuccess, response.Message);
        Assert.Single(unitOfWork.FakeRepository<ScanJob>().Added);
    }

    /// <summary>
    /// The proof that the assertion can fail on the class of bundle the upstream guards miss.
    /// </summary>
    [Fact]
    public async Task A_bundle_the_ingest_denylist_waves_through_is_still_refused()
    {
        // First, establish that this bundle really does clear every earlier guard. The
        // inspector's denylist (and the Action's identical copy of it) spells out ts/tsx/jsx
        // and omits js — so without the content policy, a Node application uploads clean.
        var inspector = new TarGzBundleInspector(NullLogger<TarGzBundleInspector>.Instance);
        await using (var probe = BundleWith(("src/app/server.js", "require('express')")))
        {
            var inspection = await inspector.InspectAsync(probe, CancellationToken.None);
            Assert.True(inspection.IsValid,
                "precondition: the ingest denylist is expected to accept a .js file");
            await inspection.RawBundle!.DisposeAsync();
        }

        var (handler, unitOfWork, store) = CreateHandler();
        await using var bundle = BundleWith(("src/app/server.js", "require('express')"));

        var response = await handler.Handle(
            new SubmitScanCommand(MetadataFor(ProjectId), bundle), CancellationToken.None);

        Assert.False(response.IsSuccess);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Contains("application source", response.Message);
        Assert.Contains("server.js", response.Message);

        // Nothing persisted, nothing stored: the refusal is before either.
        Assert.Empty(unitOfWork.FakeRepository<ScanJob>().Added);
        Assert.Empty(unitOfWork.FakeRepository<ScanBundle>().Added);
        Assert.Equal(0, unitOfWork.CompleteCallCount);
        Assert.Empty(store.Saved);
    }

    [Fact]
    public async Task A_cs_file_is_refused_and_nothing_is_persisted()
    {
        // This one the inspector catches first. Kept because the acceptance criterion is
        // about the outcome, not about which guard produced it.
        var (handler, unitOfWork, store) = CreateHandler();
        await using var bundle = BundleWith(("src/OrderApp/Program.cs", "class Program {}"));

        var response = await handler.Handle(
            new SubmitScanCommand(MetadataFor(ProjectId), bundle), CancellationToken.None);

        Assert.False(response.IsSuccess);
        Assert.Contains("application source", response.Message);
        Assert.Empty(unitOfWork.FakeRepository<ScanJob>().Added);
        Assert.Empty(store.Saved);
    }

    [Fact]
    public async Task A_file_outside_the_bundle_contract_is_refused()
    {
        var (handler, _, store) = CreateHandler();
        await using var bundle = BundleWith(("gitleaks-report.json", "[]"));

        var response = await handler.Handle(
            new SubmitScanCommand(MetadataFor(ProjectId), bundle), CancellationToken.None);

        Assert.False(response.IsSuccess);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Contains("outside the bundle contract", response.Message);
        Assert.Empty(store.Saved);
    }

    // ---- box 1: egress restricted to allowed endpoints ------------------------------------

    [Fact]
    public async Task A_job_is_refused_while_the_deployment_points_off_the_allowlist()
    {
        var (handler, unitOfWork, store) = CreateHandler(
            FakeEgress.PointedAt("https://exfil.example.com/v1"));

        await using var bundle = BundleWith();

        var response = await handler.Handle(
            new SubmitScanCommand(MetadataFor(ProjectId), bundle), CancellationToken.None);

        Assert.False(response.IsSuccess);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("exfil.example.com", response.Message);

        // Refused before the bundle is even read, so nothing was stored or recorded.
        Assert.Empty(unitOfWork.FakeRepository<ScanJob>().Added);
        Assert.Empty(store.Saved);
    }

    [Fact]
    public async Task The_same_job_is_accepted_when_the_endpoint_is_an_allowed_provider()
    {
        // The other half of the pair. Without it, the test above would pass just as happily
        // against a check that refused everything.
        var (handler, unitOfWork, _) = CreateHandler(
            FakeEgress.PointedAt("https://api.anthropic.com/v1"));

        await using var bundle = BundleWith();

        var response = await handler.Handle(
            new SubmitScanCommand(MetadataFor(ProjectId), bundle), CancellationToken.None);

        Assert.True(response.IsSuccess, response.Message);
        Assert.Single(unitOfWork.FakeRepository<ScanJob>().Added);
    }
}

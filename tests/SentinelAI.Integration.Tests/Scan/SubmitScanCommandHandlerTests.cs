using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Commands.Submit;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Implementation.Repositories;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// The two SEC-13 acceptance paths, exercised against the real
/// <see cref="TarGzBundleInspector"/> with fakes standing in for storage/persistence/auth.
/// </summary>
public class SubmitScanCommandHandlerTests
{
    private static readonly Guid TenantId = Guid.NewGuid();
    private static readonly Guid ProjectId = Guid.NewGuid();

    private static (SubmitScanCommandHandler Handler, FakeUnitOfWork UnitOfWork, FakeBundleStore Store)
        CreateHandler()
    {
        var project = new Project { Id = ProjectId, TenantId = TenantId };
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository { Project = project });
        var store = new FakeBundleStore();
        var inspector = new TarGzBundleInspector(NullLogger<TarGzBundleInspector>.Instance);
        var corpus = new FakeCorpusVersionProvider();
        var caller = new FakeCallerContext { TenantId = TenantId };

        var handler = new SubmitScanCommandHandler(
            unitOfWork, inspector, store, corpus, caller, FakeEgress.Offline());
        return (handler, unitOfWork, store);
    }

    private static string MetadataFor(Guid projectId) => $$"""
        {
          "project_id": "{{projectId}}",
          "commit_sha": "abc123",
          "artifacts": [{ "kind": "sarif", "tool": "osv-scanner", "filename": "findings/osv.sarif" }]
        }
        """;

    [Fact]
    public async Task Valid_bundle_creates_a_scan_job_and_a_scan_bundle_row_and_returns_202()
    {
        var (handler, unitOfWork, store) = CreateHandler();
        await using var bundle = TarGzTestHelper.Build(new Dictionary<string, string>
        {
            ["metadata.json"] = MetadataFor(ProjectId),
            ["findings/osv.sarif"] = "{}",
        });

        var response = await handler.Handle(new SubmitScanCommand(MetadataFor(ProjectId), bundle), CancellationToken.None);

        Assert.True(response.IsSuccess, response.Message);
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        var jobs = unitOfWork.FakeRepository<ScanJob>().Added;
        var bundles = unitOfWork.FakeRepository<ScanBundle>().Added;
        Assert.Single(jobs);
        Assert.Single(bundles);
        Assert.Equal(1, unitOfWork.CompleteCallCount);

        var job = jobs[0];
        Assert.Equal(ProjectId, job.ProjectId);
        Assert.Equal(ScanStatus.Queued, job.Status);
        Assert.Equal(ScanStage.Received, job.Stage);

        var bundleRow = bundles[0];
        Assert.Equal(job.Id, bundleRow.ScanJobId);
        Assert.NotEmpty(bundleRow.Sha256);
        Assert.True(bundleRow.SizeBytes > 0);

        // Provenance: the file list and scanner versions are on the record, not just the hash.
        Assert.Contains("osv.sarif", bundleRow.ArtifactManifest);

        // What actually landed in storage matches what the row claims — this is the
        // regression guard for the double-read bug (storage must not see a truncated bundle).
        Assert.True(store.Saved.TryGetValue(job.Id, out var storedBytes));
        Assert.Equal(bundleRow.SizeBytes, storedBytes!.Length);

        var body = Assert.IsType<SubmitScanResponse>(response.Data);
        Assert.Equal($"/v1/scans/{job.Id}", body.PollUrl);
    }

    [Fact]
    public async Task Bundle_with_a_cs_file_is_rejected_and_nothing_is_persisted()
    {
        var (handler, unitOfWork, store) = CreateHandler();
        await using var bundle = TarGzTestHelper.Build(new Dictionary<string, string>
        {
            ["metadata.json"] = MetadataFor(ProjectId),
            ["findings/osv.sarif"] = "{}",
            ["src/Program.cs"] = "class Program {}",
        });

        var response = await handler.Handle(new SubmitScanCommand(MetadataFor(ProjectId), bundle), CancellationToken.None);

        Assert.False(response.IsSuccess);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Contains("application source", response.Message);

        Assert.Empty(unitOfWork.FakeRepository<ScanJob>().Added);
        Assert.Empty(unitOfWork.FakeRepository<ScanBundle>().Added);
        Assert.Equal(0, unitOfWork.CompleteCallCount);
        Assert.Empty(store.Saved);
    }
}

using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// Findings had no persistence until SEC-20 needed one: <c>chain_hops.finding_id</c> is a foreign
/// key, so a chain written against an in-memory-only finding is rejected by the database with the
/// whole batch. These pin the writer that closed that gap.
/// </summary>
public class NormalizedFindingWriterTests
{
    private static readonly Guid Tenant = Guid.NewGuid();

    private static Finding Finding(Guid scanJobId, string nodeRef, int severity = 7) => new()
    {
        Id = Guid.CreateVersion7(),
        TenantId = Tenant,
        ScanJobId = scanJobId,
        SourceTool = "checkov",
        Layer = Layer.Infra,
        Severity = severity,
        NodeRef = nodeRef,
        Message = "test finding",
    };

    private static NormalizedFindingWriter Writer(FakeUnitOfWork unitOfWork) =>
        new(unitOfWork, NullLogger<NormalizedFindingWriter>.Instance);

    [Fact]
    public async Task A_normalization_runs_findings_become_rows()
    {
        var job = Guid.NewGuid();
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var findings = new[] { Finding(job, "iam_role:order_task_role"), Finding(job, "resource:orders") };

        await Writer(unitOfWork).WriteAsync(findings, job, CancellationToken.None);

        Assert.Equal(2, unitOfWork.FakeRepository<Finding>().Added.Count);
        Assert.Equal(1, unitOfWork.CompleteCallCount);
    }

    [Fact]
    public async Task Re_running_the_stage_replaces_the_previous_runs_findings_rather_than_doubling_them()
    {
        var job = Guid.NewGuid();
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var stale = Finding(job, "iam_role:order_task_role");
        unitOfWork.FakeRepository<Finding>().Added.Add(stale);

        await Writer(unitOfWork).WriteAsync([Finding(job, "iam_role:order_task_role")], job, CancellationToken.None);

        var stored = unitOfWork.FakeRepository<Finding>();
        Assert.Single(stored.Added);
        Assert.DoesNotContain(stale, stored.Added);
        Assert.Contains(stale, stored.Deleted);
    }

    [Fact]
    public async Task Another_jobs_findings_survive_the_clear()
    {
        var job = Guid.NewGuid();
        var other = Finding(Guid.NewGuid(), "pkg:newtonsoft.json");
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        unitOfWork.FakeRepository<Finding>().Added.Add(other);

        await Writer(unitOfWork).WriteAsync([Finding(job, "code:src/Orders")], job, CancellationToken.None);

        Assert.Contains(other, unitOfWork.FakeRepository<Finding>().Added);
        Assert.Empty(unitOfWork.FakeRepository<Finding>().Deleted);
    }

    /// <summary>
    /// The findings cannot go until the rows pointing at them do — that is the same foreign key,
    /// read from the other end.
    /// </summary>
    [Fact]
    public async Task The_previous_runs_chains_and_hops_go_with_its_findings()
    {
        var job = Guid.NewGuid();
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var stale = Finding(job, "iam_role:order_task_role");

        var chain = new Chain
        {
            Id = Guid.CreateVersion7(),
            TenantId = Tenant,
            ScanJobId = job,
            HopCount = 1,
            Priority = 1,
            Status = ChainStatus.Candidate,
            MinConfidence = Confidence.Inferred,
        };

        var hop = new ChainHop
        {
            Id = Guid.CreateVersion7(),
            TenantId = Tenant,
            ChainId = chain.Id,
            HopOrder = 0,
            FindingId = stale.Id,
        };

        var citation = new Citation
        {
            Id = Guid.CreateVersion7(),
            TenantId = Tenant,
            ChainHopId = hop.Id,
            KnowledgeId = "k1",
        };

        unitOfWork.FakeRepository<Finding>().Added.Add(stale);
        unitOfWork.FakeRepository<Chain>().Added.Add(chain);
        unitOfWork.FakeRepository<ChainHop>().Added.Add(hop);
        unitOfWork.FakeRepository<Citation>().Added.Add(citation);

        await Writer(unitOfWork).WriteAsync([Finding(job, "iam_role:order_task_role")], job, CancellationToken.None);

        Assert.Empty(unitOfWork.FakeRepository<Chain>().Added);
        Assert.Empty(unitOfWork.FakeRepository<ChainHop>().Added);
        Assert.Empty(unitOfWork.FakeRepository<Citation>().Added);
    }

    [Fact]
    public async Task A_scan_that_found_nothing_is_not_an_error()
    {
        var job = Guid.NewGuid();
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());

        await Writer(unitOfWork).WriteAsync([], job, CancellationToken.None);

        Assert.Empty(unitOfWork.FakeRepository<Finding>().Added);
        Assert.Equal(1, unitOfWork.CompleteCallCount);
    }
}

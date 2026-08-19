using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Scan.Graph;

/// <summary>
/// SEC-28's write-back: the debate's outcome must reach the top-priority chain row
/// <see cref="CandidateChainWriter"/> left at <see cref="ChainStatus.Candidate"/>, so
/// <c>GET /v1/scans/{id}/chains</c> can tell a chain the debate validated from one nobody has
/// looked at yet.
/// </summary>
public class ChainOutcomeWriterTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private static ChainOutcomeWriter Writer(FakeUnitOfWork unitOfWork) =>
        new(unitOfWork, NullLogger<ChainOutcomeWriter>.Instance);

    private static Chain Chain(int priority) => new()
    {
        Id = Guid.CreateVersion7(),
        TenantId = Tenant,
        ScanJobId = Job,
        HopCount = 4,
        Priority = priority,
        Status = ChainStatus.Candidate,
        MinConfidence = Confidence.Inferred,
    };

    private static DraftAudit Audit(
        bool verdictReadable = true,
        bool terminatedByTurnCap = false,
        bool converged = false,
        IReadOnlyList<string>? edgeIntegrityWarnings = null) => new()
    {
        Summary = "test",
        Transcript = [],
        Rounds = 1,
        TerminatedByTurnCap = terminatedByTurnCap,
        Converged = converged,
        VerdictReadable = verdictReadable,
        EdgeIntegrityWarnings = edgeIntegrityWarnings ?? [],
    };

    [Fact]
    public async Task A_converged_debate_promotes_the_chain_to_validated()
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var chain = Chain(priority: 1);
        unitOfWork.FakeRepository<Chain>().Added.Add(chain);

        await Writer(unitOfWork).ApplyAsync(Job, Audit(converged: true), brief: null, CancellationToken.None);

        Assert.Equal(ChainStatus.Validated, chain.Status);
        Assert.True(unitOfWork.CompleteCallCount > 0);
    }

    /// <summary>
    /// SEC-50: a converged debate whose mechanical edge check found a hop that doesn't match the
    /// graph is capped at Asserted, never Validated. Blue's own verdict said the chain holds; the
    /// mechanical check is what caught the one live case where that verdict was wrong.
    /// </summary>
    [Fact]
    public async Task A_converged_debate_with_edge_integrity_warnings_is_capped_at_asserted()
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var chain = Chain(priority: 1);
        unitOfWork.FakeRepository<Chain>().Added.Add(chain);

        var audit = Audit(converged: true, edgeIntegrityWarnings: ["N3 -> N69 does not match the graph"]);
        await Writer(unitOfWork).ApplyAsync(Job, audit, brief: null, CancellationToken.None);

        Assert.Equal(ChainStatus.Asserted, chain.Status);
    }

    /// <summary>A broken chain stays rejected regardless of what the edge check found — it is
    /// already the worst outcome, and a mechanical warning cannot make a discarded chain worse.</summary>
    [Fact]
    public async Task A_broken_chain_with_edge_integrity_warnings_stays_rejected()
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var chain = Chain(priority: 1);
        unitOfWork.FakeRepository<Chain>().Added.Add(chain);

        var audit = Audit(converged: false, edgeIntegrityWarnings: ["N1 -> N9 not found"]);
        await Writer(unitOfWork).ApplyAsync(Job, audit, brief: null, CancellationToken.None);

        Assert.Equal(ChainStatus.Rejected, chain.Status);
    }

    [Fact]
    public async Task A_broken_chain_is_rejected()
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var chain = Chain(priority: 1);
        unitOfWork.FakeRepository<Chain>().Added.Add(chain);

        // Readable, not converged, not capped — DraftAudit.Outcome's ChainBroken branch.
        await Writer(unitOfWork).ApplyAsync(
            Job, Audit(verdictReadable: true, terminatedByTurnCap: false, converged: false),
            brief: null, CancellationToken.None);

        Assert.Equal(ChainStatus.Rejected, chain.Status);
    }

    [Theory]
    [InlineData(false, false)] // verdict unreadable
    [InlineData(true, true)]   // turn-capped, never converged
    public async Task An_inconclusive_debate_only_reaches_asserted_not_validated_or_rejected(
        bool verdictReadable, bool terminatedByTurnCap)
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var chain = Chain(priority: 1);
        unitOfWork.FakeRepository<Chain>().Added.Add(chain);

        await Writer(unitOfWork).ApplyAsync(
            Job, Audit(verdictReadable, terminatedByTurnCap, converged: false), brief: null,
            CancellationToken.None);

        // Red ran and asserted something, but nothing confirmed or refuted it — "unreadable" or
        // "ran out of turns" is not evidence the chain is real or fake (AID-01 §3.3).
        Assert.Equal(ChainStatus.Asserted, chain.Status);
    }

    [Fact]
    public async Task The_top_priority_chain_is_the_one_promoted_when_several_candidates_exist()
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var flagship = Chain(priority: 1);
        var runnerUp = Chain(priority: 2);
        unitOfWork.FakeRepository<Chain>().Added.AddRange([runnerUp, flagship]);

        await Writer(unitOfWork).ApplyAsync(Job, Audit(converged: true), brief: null, CancellationToken.None);

        Assert.Equal(ChainStatus.Validated, flagship.Status);
        Assert.Equal(ChainStatus.Candidate, runnerUp.Status);
    }

    /// <summary>
    /// The walking skeleton, or a graph the traverser found no candidates over. Nothing to
    /// promote is not a failure — it is the honest state of a scan with no chain rows at all.
    /// </summary>
    [Fact]
    public async Task A_scan_job_with_no_persisted_chains_is_not_an_error()
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());

        await Writer(unitOfWork).ApplyAsync(Job, Audit(converged: true), brief: null, CancellationToken.None);

        Assert.Empty(unitOfWork.FakeRepository<Chain>().Updated);
        Assert.Equal(0, unitOfWork.CompleteCallCount);
    }

    /// <summary>A chain belonging to a different scan job must never be touched.</summary>
    [Fact]
    public async Task Only_this_scan_jobs_chain_is_promoted()
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var thisJobsChain = Chain(priority: 1);
        var otherJobsChain = new Chain
        {
            Id = Guid.CreateVersion7(),
            TenantId = Tenant,
            ScanJobId = Guid.NewGuid(),
            HopCount = 2,
            Priority = 1,
            Status = ChainStatus.Candidate,
        };
        unitOfWork.FakeRepository<Chain>().Added.AddRange([thisJobsChain, otherJobsChain]);

        await Writer(unitOfWork).ApplyAsync(Job, Audit(converged: true), brief: null, CancellationToken.None);

        Assert.Equal(ChainStatus.Validated, thisJobsChain.Status);
        Assert.Equal(ChainStatus.Candidate, otherJobsChain.Status);
    }
}

using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Commands.RunGraph;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Integration.Tests.Scan.Graph;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// The manual trigger behind <c>POST /v1/scans/{id}/graph</c>. The pipeline it runs is covered by
/// <c>GraphStagePipelineTests</c>; this covers the handler's own responsibilities — the gates in
/// front of it and what it records about the job afterward.
/// </summary>
public class RunGraphStageCommandHandlerTests
{
    private static readonly Guid Tenant = Guid.NewGuid();

    private static ScanJob Job(bool purged = false) => new()
    {
        Id = Guid.NewGuid(),
        TenantId = Tenant,
        ProjectId = Guid.NewGuid(),
        Status = ScanStatus.Queued,
        Stage = ScanStage.Received,
        BundlePurged = purged,
        StartedAt = DateTime.UtcNow,
    };

    private static RunGraphStageCommandHandler Handler(
        IUnitOfWork unitOfWork, ICallerContext caller, IBundleStore store)
    {
        var normalization = new NormalizationPipeline(
            [], store,
            new RuleMappingResolver(new NoRuleMappings(), NullLogger<RuleMappingResolver>.Instance),
            new FindingUnifier(),
            NullLogger<NormalizationPipeline>.Instance);

        var graphStage = new GraphStagePipeline(
            store,
            new InfraSpineWriter(store, new NoInfraSpine(), unitOfWork, NullLogger<InfraSpineWriter>.Instance),
            new DepCodeSeamWriter(new NoDepCode(), unitOfWork, NullLogger<DepCodeSeamWriter>.Instance),
            new CodeInfraSeamWriter(new NoCodeInfra(), unitOfWork, NullLogger<CodeInfraSeamWriter>.Instance),
            new RoleResourceSeamWriter(new NoRoleResource(), unitOfWork, NullLogger<RoleResourceSeamWriter>.Instance),
            new CandidateChainWriter(
                store, new NoInfraFindings(),
                new GraphDecorator(NullLogger<GraphDecorator>.Instance),
                new ExploitChainTraverser(NullLogger<ExploitChainTraverser>.Instance),
                unitOfWork, NullLogger<CandidateChainWriter>.Instance),
            NullLogger<GraphStagePipeline>.Instance);

        return new RunGraphStageCommandHandler(
            unitOfWork, caller, normalization, graphStage, NullLogger<RunGraphStageCommandHandler>.Instance);
    }

    private static (FakeUnitOfWork UnitOfWork, ScanJob Job) SeededJob(bool withBundle = true, bool purged = false)
    {
        var job = Job(purged);
        var unitOfWork = new FakeUnitOfWork(new StubScanJobRepository(job));

        if (withBundle)
        {
            unitOfWork.FakeRepository<ScanBundle>().Added.Add(new ScanBundle
            {
                Id = Guid.NewGuid(),
                TenantId = Tenant,
                ScanJobId = job.Id,
                StorageLocator = "fake://bundle",
            });
        }

        return (unitOfWork, job);
    }

    [Fact]
    public async Task An_anonymous_caller_is_refused()
    {
        var (unitOfWork, job) = SeededJob();
        var caller = new FakeCallerContext { IsAuthenticated = false, TenantId = null };

        var response = await Handler(unitOfWork, caller, new FakeGraphInputsStore())
            .Handle(new RunGraphStageCommand(job.Id), CancellationToken.None);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>Running the stage writes graph and chain rows, so it needs a write scope.</summary>
    [Fact]
    public async Task A_read_only_caller_is_refused()
    {
        var (unitOfWork, job) = SeededJob();
        var caller = new FakeCallerContext { TenantId = Tenant, Scopes = [AuthScopes.ScanRead] };

        var response = await Handler(unitOfWork, caller, new FakeGraphInputsStore())
            .Handle(new RunGraphStageCommand(job.Id), CancellationToken.None);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Another tenant's job is indistinguishable from one that does not exist — a 403 would
    /// confirm it does (SEC-32).
    /// </summary>
    [Fact]
    public async Task Another_tenants_job_looks_like_a_missing_one()
    {
        var (unitOfWork, job) = SeededJob();
        var caller = new FakeCallerContext { TenantId = Guid.NewGuid(), Scopes = [AuthScopes.ScanWrite] };

        var response = await Handler(unitOfWork, caller, new FakeGraphInputsStore())
            .Handle(new RunGraphStageCommand(job.Id), CancellationToken.None);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task A_purged_bundle_reports_gone_rather_than_a_confusing_empty_graph()
    {
        var (unitOfWork, job) = SeededJob(purged: true);
        var caller = new FakeCallerContext { TenantId = Tenant, Scopes = [AuthScopes.ScanWrite] };

        var response = await Handler(unitOfWork, caller, new FakeGraphInputsStore())
            .Handle(new RunGraphStageCommand(job.Id), CancellationToken.None);

        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
    }

    [Fact]
    public async Task A_job_with_no_stored_bundle_is_a_conflict()
    {
        var (unitOfWork, job) = SeededJob(withBundle: false);
        var caller = new FakeCallerContext { TenantId = Tenant, Scopes = [AuthScopes.ScanWrite] };

        var response = await Handler(unitOfWork, caller, new FakeGraphInputsStore())
            .Handle(new RunGraphStageCommand(job.Id), CancellationToken.None);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task A_successful_run_advances_the_job_to_the_graph_stage()
    {
        var (unitOfWork, job) = SeededJob();
        var caller = new FakeCallerContext { TenantId = Tenant, Scopes = [AuthScopes.ScanWrite] };

        var response = await Handler(unitOfWork, caller, new FakeGraphInputsStore { Files = new() })
            .Handle(new RunGraphStageCommand(job.Id), CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.IsSuccess);

        Assert.Equal(ScanStage.Graph, job.Stage);
        Assert.Equal(ScanStatus.Running, job.Status);
        Assert.Contains(job, unitOfWork.FakeRepository<ScanJob>().Updated);

        var data = Assert.IsType<RunGraphStageResponse>(response.Data);
        Assert.Equal(job.Id.ToString(), data.ScanJobId);
        Assert.NotEmpty(data.Disclaimer);
    }

    /// <summary>
    /// The stage is synchronous, so the caller sees the failure — but the job row is what a later
    /// reader looks at, so the reason is recorded there too rather than the job sitting silently
    /// at its old stage.
    /// </summary>
    [Fact]
    public async Task A_failing_run_records_the_reason_on_the_job()
    {
        var (unitOfWork, job) = SeededJob();
        var caller = new FakeCallerContext { TenantId = Tenant, Scopes = [AuthScopes.ScanWrite] };

        var response = await Handler(unitOfWork, caller, new ThrowingBundleStore())
            .Handle(new RunGraphStageCommand(job.Id), CancellationToken.None);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal(ScanStatus.Failed, job.Status);
        Assert.NotNull(job.FailureReason);
    }

    private sealed class StubScanJobRepository(ScanJob job) : IScanJobRepository
    {
        public Task<ScanJob?> GetForTenantAsync(Guid scanJobId, Guid tenantId, CancellationToken ct = default)
            => Task.FromResult(job.Id == scanJobId && job.TenantId == tenantId ? job : null);

        public Task<Project?> GetProjectForTenantAsync(Guid projectId, Guid tenantId, CancellationToken ct = default)
            => Task.FromResult<Project?>(null);
    }

    private sealed class ThrowingBundleStore : IBundleStore
    {
        public Task<IReadOnlyList<StoredBundleFile>> OpenFindingsAsync(string locator, CancellationToken ct)
            => throw new IOException("bundle unreadable");

        public Task<IReadOnlyList<StoredBundleFile>> OpenGraphInputsAsync(string locator, CancellationToken ct)
            => throw new IOException("bundle unreadable");

        public Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct) => throw new NotSupportedException();
        public Task PurgeAsync(Guid scanJobId, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class NoRuleMappings : IRuleMappingLookup
    {
        public string? ResolveCwe(string sourceTool, string checkId) => null;

        public Task<IReadOnlyDictionary<RuleKey, string>> ResolveCweAsync(
            IReadOnlyCollection<RuleKey> keys, CancellationToken ct = default)
            => Task.FromResult<IReadOnlyDictionary<RuleKey, string>>(new Dictionary<RuleKey, string>());
    }

    private sealed class NoInfraSpine : IInfraSpineReader
    {
        public InfraSpineReadResult Read(InfraSpineInput input, Guid tenantId, Guid scanJobId) => new([], [], false);
    }

    private sealed class NoDepCode : IDepCodeSeamReader
    {
        public DepCodeSeamReadResult Read(DepCodeSeamInput input, Guid tenantId, Guid scanJobId) => new([], []);
    }

    private sealed class NoCodeInfra : ICodeInfraSeamReader
    {
        public CodeInfraSeamReadResult Read(CodeInfraSeamInput input, Guid tenantId, Guid scanJobId) => new([], []);
    }

    private sealed class NoRoleResource : IRoleResourceSeamReader
    {
        public RoleResourceSeamReadResult Read(RoleResourceSeamInput input, Guid tenantId, Guid scanJobId) => new([], []);
    }

    private sealed class NoInfraFindings : IInfraFindingLocator
    {
        public IReadOnlyDictionary<string, string> Locate(
            IReadOnlyDictionary<string, string> hclFiles, IEnumerable<string> findingLocations)
            => new Dictionary<string, string>();
    }
}

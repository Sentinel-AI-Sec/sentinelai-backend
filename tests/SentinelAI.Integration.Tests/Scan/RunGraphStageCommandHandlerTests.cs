using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Commands.RunGraph;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Infrastructure.Security;
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
            unitOfWork,
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

        var gate = new IngressRedactionGate(
            new RegexSecretScanner(), store, NullLogger<IngressRedactionGate>.Instance);

        var findingWriter = new NormalizedFindingWriter(
            unitOfWork, NullLogger<NormalizedFindingWriter>.Instance);

        return new RunGraphStageCommandHandler(
            unitOfWork, caller, normalization, gate, findingWriter, graphStage,
            new ScanBriefRenderer(),
            NullLogger<RunGraphStageCommandHandler>.Instance);
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

    /// <summary>
    /// SEC-33 in the real pipeline: the gate runs inside this handler, so a bundle carrying a
    /// hardcoded credential comes out of the stage redacted, flagged, and reported.
    /// </summary>
    [Fact]
    public async Task A_successful_run_applies_the_ingress_gate_and_records_it()
    {
        var (unitOfWork, job) = SeededJob();
        var caller = new FakeCallerContext { TenantId = Tenant, Scopes = [AuthScopes.ScanWrite] };

        // The reference fixture's INFRA-07: a key baked into the image via ENV.
        var store = new FakeGraphInputsStore
        {
            Files = new(StringComparer.OrdinalIgnoreCase)
            {
                ["graph-inputs/Dockerfile"] =
                    "FROM base\nENV ORDER_SVC_API_KEY=\"demo-fixture-dummy-key-not-real-000111\"\n",
            },
        };

        var response = await Handler(unitOfWork, caller, store)
            .Handle(new RunGraphStageCommand(job.Id), CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The auditable claim: scan_bundles.ingress_redaction_applied.
        var bundle = Assert.Single(unitOfWork.FakeRepository<ScanBundle>().Added);
        Assert.True(bundle.IngressRedactionApplied);
        Assert.Contains(bundle, unitOfWork.FakeRepository<ScanBundle>().Updated);

        // The customer-facing half: the credential is reported, at the top severity.
        var secret = Assert.Single(unitOfWork.FakeRepository<Finding>().Added);
        Assert.Equal(ScannerNames.IngressGate, secret.SourceTool);
        Assert.Equal(IngressRedactionGate.HardcodedSecretCwe, secret.CweId);
        Assert.Equal(IngressRedactionGate.SecretSeverity, secret.Severity);
        Assert.True(secret.Redacted);
        Assert.DoesNotContain(
            "demo-fixture-dummy-key-not-real-000111", secret.Message, StringComparison.Ordinal);

        var data = Assert.IsType<RunGraphStageResponse>(response.Data);
        Assert.Equal(1, data.HardcodedSecrets);
    }

    /// <summary>
    /// The flag records that the gate ran, not that it found something — <c>false</c> has to
    /// keep meaning "nobody looked", or it proves nothing.
    /// </summary>
    [Fact]
    public async Task The_redaction_flag_is_set_even_when_the_bundle_is_clean()
    {
        var (unitOfWork, job) = SeededJob();
        var caller = new FakeCallerContext { TenantId = Tenant, Scopes = [AuthScopes.ScanWrite] };

        await Handler(unitOfWork, caller, new FakeGraphInputsStore { Files = new() })
            .Handle(new RunGraphStageCommand(job.Id), CancellationToken.None);

        Assert.True(Assert.Single(unitOfWork.FakeRepository<ScanBundle>().Added).IngressRedactionApplied);
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

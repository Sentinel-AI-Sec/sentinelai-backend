using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Debate;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Application.Features.Scan.Orchestration;
using SentinelAI.Application.Features.Scan.Reporting;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Application.Features.Scan.ThinSlice;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Graph;
using SentinelAI.Infrastructure.Implementation;
using SentinelAI.Infrastructure.Implementation.Repositories;
using SentinelAI.Infrastructure.Knowledge;
using SentinelAI.Infrastructure.Normalization;
using SentinelAI.Infrastructure.Security;

using SentinelAI.Integration.Tests.Scan;
using SentinelAI.Application.Features.Scan.Audit;

namespace SentinelAI.Integration.Tests.Scan.Orchestration;

/// <summary>
/// SEC-46's acceptance criteria, one test each: a bundle runs the whole flow automatically, the
/// stages run in order, a failure names the stage that broke, and the scan target never reaches
/// the knowledge corpus.
/// </summary>
/// <remarks>
/// <para>
/// <b>The runner, not the worker.</b> Everything SEC-46 promises about a scan is a property of
/// <see cref="ScanPipelineRunner"/>; the worker only decides <em>when</em> it runs. Driving the
/// runner directly makes these tests deterministic — no polling, no background thread, no
/// waiting on a claim — and the two things the worker adds on top (the atomic claim, and
/// assuming the claimed tenant) are its own concerns rather than the pipeline's.
/// </para>
/// <para>
/// <b>Nothing the project owns is stubbed.</b> The real normalization stage, the real graph
/// stage over a real <c>.tar.gz</c>, the real debate engine over the scripted provider, and a
/// real <c>DbContext</c>. The two fakes are the corpus, which does not exist yet (SEC-09), and
/// retention, which deletes things a test wants to read.
/// </para>
/// </remarks>
public sealed class ScanPipelineRunnerTests : IDisposable
{
    private static readonly Guid Tenant = Guid.NewGuid();

    private readonly string _root = Path.Combine(Path.GetTempPath(), $"sentinelai-sec46-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
        GC.SuppressFinalize(this);
    }

    // ---- The bundle -----------------------------------------------------------------------

    /// <summary>The finding that carries the flagship chain, emitted by the real Roslyn extractor.</summary>
    private const string RoslynSarif = """
    {
      "version": "2.1.0",
      "runs": [{
        "tool": { "driver": { "name": "SecurityCodeScan", "rules": [{ "id": "SCS0028" }] } },
        "results": [{
          "ruleId": "SCS0028", "level": "warning",
          "message": { "text": "TypeNameHandling is set to the other value than 'None'. It may lead to deserialization vulnerability." },
          "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": "file:///src/OrderApp/Controllers/OrdersController.cs" },
            "region": { "startLine": 16 } } }]
        }]
      }]
    }
    """;

    private const string OsvSarif = """
    {
      "version": "2.1.0",
      "runs": [{
        "tool": { "driver": { "name": "osv-scanner", "rules": [{ "id": "CVE-2024-21907" }] } },
        "results": [{
          "ruleId": "CVE-2024-21907", "level": "warning",
          "message": { "text": "Package 'Newtonsoft.Json@12.0.1' is vulnerable to 'CVE-2024-21907'." },
          "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": "file:///src/OrderApp/packages.lock.json" } } }]
        }]
      }]
    }
    """;

    private const string InfraTf = """
    resource "aws_ecs_task_definition" "order_task" {
      family        = "order-task"
      task_role_arn = aws_iam_role.order_task_role.arn

      container_definitions = jsonencode([
        { name = "order-service", image = "registry.hub.docker.com/tinyapp/order:1.4.2" }
      ])
    }

    resource "aws_iam_role" "order_task_role" {
      name = "order-task-role"
    }

    resource "aws_iam_role_policy" "order_task_policy" {
      role = aws_iam_role.order_task_role.id

      policy = jsonencode({
        Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }]
      })
    }

    resource "aws_s3_bucket" "customer_data" {
      bucket = "sentinelai-fixture-customer-data"
    }
    """;

    private const string Dockerfile = """
    FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
    LABEL org.sentinelai.image="tinyapp/order"
    """;

    private const string LockFile = """
    {"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.1"}}}}
    """;

    /// <summary>
    /// A bundle shaped exactly like the one a runner uploads — findings on one side, the graph's
    /// inputs on the other, entry names written the way <c>tar -czf out.tar.gz -C stage .</c>
    /// emits them.
    /// </summary>
    private string WriteBundle()
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "bundle.tar.gz");

        using var archive = TarGzTestHelper.Build(new Dictionary<string, string>
        {
            ["./metadata.json"] = """{"project_id":"11111111-1111-1111-1111-111111111111"}""",
            ["./findings/roslyn.sarif"] = RoslynSarif,
            ["./findings/osv.sarif"] = OsvSarif,
            ["./graph-inputs/infra/main.tf"] = InfraTf,
            ["./graph-inputs/Dockerfile"] = Dockerfile,
            ["./graph-inputs/src/OrderApp/packages.lock.json"] = LockFile,
        });

        using var file = File.Create(path);
        archive.CopyTo(file);

        return path;
    }

    // ---- The pipeline under test ------------------------------------------------------------

    /// <summary>Everything the runner composes, wired for real over an in-memory database.</summary>
    private sealed record Harness(
        ScanPipelineRunner Runner,
        SentinelDbContext Db,
        Guid JobId,
        RecordingLogger<ScanPipelineRunner> Log,
        RecordingKnowledgeRetriever Corpus,
        CapturingRetentionPolicy Retention) : IDisposable
    {
        public void Dispose() => Db.Dispose();
    }

    /// <summary>
    /// Seeds a claimed job and builds the runner over it.
    /// </summary>
    /// <param name="bundleStore">
    /// Swapped out by the failure test to make one stage throw. Null uses the real filesystem
    /// store over the real archive.
    /// </param>
    private Harness Build(Func<IBundleStore, IBundleStore>? bundleStore = null)
    {
        var locator = WriteBundle();
        var jobId = Guid.CreateVersion7();

        var options = new DbContextOptionsBuilder<SentinelDbContext>()
            .UseInMemoryDatabase($"sec46-{Guid.NewGuid()}").Options;

        var db = new SentinelDbContext(options, new FakeCallerContext { TenantId = Tenant });
        db.Database.EnsureCreated();

        // The state the worker's claim leaves behind: Running, owned by this tenant, with its
        // bundle already stored.
        db.Set<ScanJob>().Add(new ScanJob
        {
            Id = jobId,
            TenantId = Tenant,
            Status = ScanStatus.Running,
            Stage = ScanStage.Received,
            CommitSha = "0123456789abcdef0123456789abcdef01234567",
            StartedAt = DateTime.UtcNow,
        });

        db.Set<ScanBundle>().Add(new ScanBundle
        {
            Id = Guid.CreateVersion7(),
            TenantId = Tenant,
            ScanJobId = jobId,
            StorageLocator = locator,
            ReceivedAt = DateTime.UtcNow,
        });

        db.SaveChanges();

        IUnitOfWork unitOfWork = new UnitOfWork(
            db, new ScanJobRepository(db), new UserRepository(db), new RefreshTokenRepository(db));

        IBundleStore store = new FileSystemBundleStore(
            Options.Create(new BundleStorageOptions { RootPath = _root }),
            NullLogger<FileSystemBundleStore>.Instance);

        if (bundleStore is not null) store = bundleStore(store);

        var normalization = new NormalizationPipeline(
            [new RoslynSarifExtractor(), new OsvExtractor(), new TrivySarifExtractor(), new CheckovSarifExtractor()],
            store,
            new RuleMappingResolver(new SqlRuleMappingLookup(db), NullLogger<RuleMappingResolver>.Instance),
            new FindingUnifier(),
            NullLogger<NormalizationPipeline>.Instance);

        var graphStage = new GraphStagePipeline(
            unitOfWork,
            store,
            new InfraSpineWriter(
                store,
                new TerraformInfraSpineReader(NullLogger<TerraformInfraSpineReader>.Instance),
                unitOfWork,
                NullLogger<InfraSpineWriter>.Instance),
            new DepCodeSeamWriter(
                new DepCodeSeamReader(NullLogger<DepCodeSeamReader>.Instance),
                unitOfWork,
                NullLogger<DepCodeSeamWriter>.Instance),
            new CodeInfraSeamWriter(new CodeInfraSeamReader(), unitOfWork, NullLogger<CodeInfraSeamWriter>.Instance),
            new RoleResourceSeamWriter(new RoleResourceSeamReader(), unitOfWork, NullLogger<RoleResourceSeamWriter>.Instance),
            new CandidateChainWriter(
                store,
                new TerraformFindingLocator(NullLogger<TerraformFindingLocator>.Instance),
                new GraphDecorator(NullLogger<GraphDecorator>.Instance),
                new ExploitChainTraverser(NullLogger<ExploitChainTraverser>.Instance),
                unitOfWork,
                NullLogger<CandidateChainWriter>.Instance),
            NullLogger<GraphStagePipeline>.Instance);

        var corpus = new RecordingKnowledgeRetriever(
            new SeedKnowledgeRetriever(NullLogger<SeedKnowledgeRetriever>.Instance));

        var retention = new CapturingRetentionPolicy();

        var thinSlice = new ThinSlicePipeline(
            new GraphSeeder(),
            new RetrievalQueryBuilder(),
            corpus,
            new ScanBriefRenderer(),
            new DebateEngine(
                new ChatClientFactory(new ModelProviderOptions { Provider = ModelProvider.Scripted }),
                Options.Create(new DebateOptions { MaxRounds = 2 })),
            new ReportBuilder(),
            retention,
            new FakeTenantEntitlements(),
            NullLogger<ThinSlicePipeline>.Instance);

        var log = new RecordingLogger<ScanPipelineRunner>();

        var runner = new ScanPipelineRunner(
            unitOfWork,
            normalization,
            new IngressRedactionGate(
                new RegexSecretScanner(),
                store,
                NullLogger<IngressRedactionGate>.Instance),
            new NormalizedFindingWriter(unitOfWork, NullLogger<NormalizedFindingWriter>.Instance),
            graphStage,
            thinSlice,
            new ChainOutcomeWriter(unitOfWork, NullLogger<ChainOutcomeWriter>.Instance),
            new AuditIntegrityWriter(unitOfWork, NullLogger<AuditIntegrityWriter>.Instance),
            log);

        return new Harness(runner, db, jobId, log, corpus, retention);
    }

    // ---- the run's own record ----------------------------------------------------------------

    /// <summary>
    /// A completed run leaves one integrity record behind, populated from what actually happened.
    /// </summary>
    /// <remarks>
    /// The wiring is the thing under test. The writer is easy to unit test and useless if nothing
    /// calls it, and "nothing calls it" is exactly the state the SEC-50 edge check was in — running
    /// on every debate, deciding a chain's status, and then existing only as a log line.
    /// </remarks>
    [Fact]
    public async Task A_completed_run_records_what_could_be_checked_about_it()
    {
        using var h = Build();

        var outcome = await h.Runner.RunAsync(h.JobId, Tenant);
        Assert.True(outcome.Succeeded, $"the run failed at {outcome.FailedStage}");

        var record = await h.Db.Set<ScanAuditIntegrity>().SingleAsync(a => a.ScanJobId == h.JobId);

        Assert.Equal(Tenant, record.TenantId);
        Assert.True(record.Adjudicated);
        Assert.NotEmpty(record.Outcome);
        Assert.NotEmpty(record.WeakestJoin);
        Assert.Equal(AuditIntegrityWriter.Version, record.HarnessVersion);

        // Retrieval ran, so its coverage is a measurement rather than the empty default.
        Assert.True(record.RetrievalFindings > 0, "no findings were put through retrieval");

        // Chains were produced and the debate settled exactly the strongest one.
        Assert.True(record.CandidateChains > 0, "the graph stage produced no candidate chains");
        Assert.True(
            record.ChainsAdjudicated <= record.CandidateChains,
            "more chains were adjudicated than existed");
    }

    /// <summary>
    /// One record per scan, so re-running cannot leave two rows disagreeing about what happened.
    /// </summary>
    [Fact]
    public async Task The_record_is_written_once_per_scan()
    {
        using var h = Build();

        await h.Runner.RunAsync(h.JobId, Tenant);

        Assert.Single(await h.Db.Set<ScanAuditIntegrity>().Where(a => a.ScanJobId == h.JobId).ToListAsync());
    }

    // ---- AC 1: a bundle runs the whole flow and produces a draft audit -----------------------

    [Fact]
    public async Task A_stored_bundle_runs_every_stage_without_anyone_calling_one()
    {
        using var h = Build();

        var outcome = await h.Runner.RunAsync(h.JobId, Tenant);

        Assert.True(
            outcome.Succeeded,
            $"the run failed at {outcome.FailedStage}: {outcome.FailureReason}");

        // Every stage left its own evidence behind, which is what "ran the whole flow" means
        // when no single return value carries all of it.
        Assert.NotEqual(0, outcome.Findings);
        Assert.NotEmpty(await h.Db.Set<Finding>().ToListAsync());
        Assert.NotEmpty(await h.Db.Set<GraphNode>().ToListAsync());
        Assert.NotEmpty(await h.Db.Set<GraphEdge>().ToListAsync());

        // The job itself is finished, not merely un-crashed.
        var job = await h.Db.Set<ScanJob>().SingleAsync(j => j.Id == h.JobId);

        Assert.Equal(ScanStatus.Completed, job.Status);
        Assert.Equal(ScanStage.Report, job.Stage);
        Assert.NotNull(job.CompletedAt);
        Assert.Null(job.FailureReason);

        // The criterion is "produces a draft audit", not "did not crash". This is the artifact
        // itself, caught at the point the pipeline hands it to retention.
        var report = h.Retention.Report;

        Assert.NotNull(report);
        Assert.Equal(ReportBuilder.DraftAudit, report.Framing);
        Assert.Equal(h.JobId, report.ScanJobId);
        Assert.NotEmpty(report.Summary);

        // Framed as a draft for a human, never as a verdict - the rule SEC-28 exists to hold.
        Assert.Contains("not a verified verdict", report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_audit_stage_reaches_a_verdict_on_the_chains_the_graph_found()
    {
        using var h = Build();

        var outcome = await h.Runner.RunAsync(h.JobId, Tenant);

        Assert.True(outcome.Succeeded, outcome.FailureReason);
        Assert.NotEqual(0, outcome.CandidateChains);

        // SEC-28: the debate's conclusion is written back onto the graph stage's chain rows. A
        // chain still sitting at Candidate after a completed run means the audit stage produced
        // a draft audit nobody applied.
        var chains = await h.Db.Set<Chain>().ToListAsync();

        Assert.NotEmpty(chains);
        Assert.Contains(chains, c => c.Status != ChainStatus.Candidate);
    }

    // ---- AC 2: stages run in the correct order ----------------------------------------------

    [Fact]
    public async Task The_stages_run_in_the_order_the_pipeline_defines()
    {
        using var h = Build();

        await h.Runner.RunAsync(h.JobId, Tenant);

        // Read off the runner's own stage log rather than inferred from the rows: the rows say
        // what exists at the end, and this criterion is about sequence.
        var order = h.Log.StagesInOrder();

        Assert.Equal(
            [ScanPipelineStage.Normalize, ScanPipelineStage.Graph, ScanPipelineStage.Audit],
            order);
    }

    // ---- AC 3: the scan target is never added to the knowledge corpus ------------------------

    /// <summary>
    /// The rule the sprint document names as SEC-46's one common mistake, pinned two ways.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The behavioural half — that a real run never writes — is only as strong as the fake it
    /// runs against, so it is backed by the structural half: the corpus-facing ports expose no
    /// way to write at all. Together they fail in both directions that matter. If someone adds
    /// an ingest method to a port, the structural assertion breaks even if nothing calls it
    /// yet; if someone calls an existing port in a new place, the recorder sees it.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Pipeline_B_never_writes_the_scan_target_into_the_corpus()
    {
        using var h = Build();

        var outcome = await h.Runner.RunAsync(h.JobId, Tenant);

        Assert.True(outcome.Succeeded, outcome.FailureReason);

        // It read — the audit stage is grounded — and reading is all it did.
        Assert.NotEqual(0, h.Corpus.Retrievals);

        Type[] corpusPorts = [typeof(IKnowledgeRetriever), typeof(IKnowledgeSearch), typeof(IQueryEmbedder)];

        string[] writeVerbs =
            ["Write", "Upsert", "Insert", "Index", "Ingest", "Add", "Store", "Save", "Embed", "Delete", "Put"];

        foreach (var port in corpusPorts)
        {
            foreach (var method in port.GetMethods())
            {
                // EmbedAsync is the one method whose name reads like a write and is not: it turns
                // a query string into vectors and returns them to the caller. Named explicitly
                // rather than dropped from the verb list, so an EmbedAndStoreAsync would still
                // be caught.
                if (method.Name == nameof(IQueryEmbedder.EmbedAsync)) continue;

                Assert.DoesNotContain(
                    writeVerbs,
                    verb => method.Name.StartsWith(verb, StringComparison.Ordinal));
            }
        }
    }

    // ---- AC 4: a failure identifies which stage broke ----------------------------------------

    [Fact]
    public async Task A_stage_that_throws_fails_the_job_and_names_itself()
    {
        // The graph stage is the one that reads graph-inputs/, so refusing that read fails it and
        // nothing before it — which is what makes the attribution worth asserting.
        using var h = Build(real => new FailsOnGraphInputs(real));

        var outcome = await h.Runner.RunAsync(h.JobId, Tenant);

        Assert.False(outcome.Succeeded);
        Assert.Equal(ScanPipelineStage.Graph, outcome.FailedStage);

        var job = await h.Db.Set<ScanJob>().SingleAsync(j => j.Id == h.JobId);

        Assert.Equal(ScanStatus.Failed, job.Status);
        Assert.NotNull(job.CompletedAt);

        // The stage is on the row and not only in the return value: a failure nobody was
        // watching live has to be diagnosable from the database alone.
        Assert.StartsWith($"[{ScanPipelineStage.Graph}]", job.FailureReason);

        // The stage before it still committed its work. A failed run is not a rolled-back one,
        // and the findings are what make the failure investigable.
        Assert.NotEmpty(await h.Db.Set<Finding>().ToListAsync());
    }

    [Fact]
    public async Task A_job_whose_bundle_is_gone_fails_instead_of_reporting_a_clean_scan()
    {
        using var h = Build();

        var job = await h.Db.Set<ScanJob>().SingleAsync(j => j.Id == h.JobId);
        job.BundlePurged = true;
        await h.Db.SaveChangesAsync();

        var outcome = await h.Runner.RunAsync(h.JobId, Tenant);

        // The dangerous shape this guards against: no bundle means no findings, and a report
        // over no findings reads exactly like a clean scan.
        Assert.False(outcome.Succeeded);
        Assert.Empty(await h.Db.Set<Finding>().ToListAsync());

        var failed = await h.Db.Set<ScanJob>().SingleAsync(j => j.Id == h.JobId);
        Assert.Equal(ScanStatus.Failed, failed.Status);
    }

    // ---- Test doubles ------------------------------------------------------------------------

    /// <summary>Refuses the read the graph stage depends on, and only that one.</summary>
    private sealed class FailsOnGraphInputs(IBundleStore inner) : IBundleStore
    {
        public Task<IReadOnlyList<StoredBundleFile>> OpenFindingsAsync(string locator, CancellationToken ct)
            => inner.OpenFindingsAsync(locator, ct);

        public Task<IReadOnlyList<StoredBundleFile>> OpenGraphInputsAsync(string locator, CancellationToken ct)
            => throw new IOException("the bundle's graph inputs could not be read");

        public Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct)
            => inner.SaveAsync(scanJobId, bundle, ct);

        public Task PurgeAsync(Guid scanJobId, CancellationToken ct) => inner.PurgeAsync(scanJobId, ct);
    }

    /// <summary>
    /// Keeps the report the pipeline handed to retention.
    /// </summary>
    /// <remarks>
    /// The runner does not return the report — retention is its last stage and decides whether it
    /// is kept at all — so this is the one place the draft audit is observable from outside the
    /// pipeline without also opting into persistence and the bundle purge that comes with it.
    /// </remarks>
    private sealed class CapturingRetentionPolicy : IScanRetentionPolicy
    {
        public Report? Report { get; private set; }

        public Task<RetentionOutcome> ApplyAfterAuditAsync(
            Guid tenantId, Guid scanJobId, Report report, CancellationToken ct = default)
        {
            Report = report;
            report.Retained = false;

            return Task.FromResult(new RetentionOutcome(BundlePurged: true, ReportRetained: false));
        }
    }

    /// <summary>Counts what the pipeline asked the corpus to do.</summary>
    private sealed class RecordingKnowledgeRetriever(IKnowledgeRetriever inner) : IKnowledgeRetriever
    {
        public int Retrievals { get; private set; }

        public Task<RetrievalResult> RetrieveAsync(
            Finding finding, RetrievalIntent intent, CancellationToken ct = default)
        {
            Retrievals++;
            return inner.RetrieveAsync(finding, intent, ct);
        }
    }

    /// <summary>Keeps the runner's stage messages so their order can be asserted.</summary>
    private sealed class RecordingLogger<T> : ILogger<T>
    {
        private readonly List<string> _messages = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => _messages.Add(formatter(state, exception));

        /// <summary>
        /// The stages in the order they started. Keyed off the "started" line specifically —
        /// "completed" would report the order they finished, which for a sequential pipeline is
        /// the same list and for a broken one would hide an overlap.
        /// </summary>
        public IReadOnlyList<ScanPipelineStage> StagesInOrder() =>
        [
            .. _messages
                .Where(m => m.StartsWith("Stage ", StringComparison.Ordinal) && m.Contains(" started ", StringComparison.Ordinal))
                .Select(m => Enum.Parse<ScanPipelineStage>(m.Split(' ')[1]))
        ];
    }
}

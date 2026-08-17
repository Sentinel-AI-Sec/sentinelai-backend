using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Application.Features.Scan.ThinSlice;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Orchestration;

/// <summary>
/// Runs one claimed scan job through every stage of Pipeline B (SEC-46).
/// </summary>
/// <remarks>
/// <para>
/// <b>What this is, and what it is not.</b> It owns the <em>order</em> of the stages and the
/// <em>bookkeeping</em> around them — status, timestamps, which block failed. It owns none of the
/// stages themselves: every one is an existing service called through its existing public method.
/// If a stage is wrong, it is wrong in its own class and its own ticket, not here.
/// </para>
/// <para>
/// <b>Why not reuse <c>RunGraphStageCommand</c> and <c>RunAuditStageCommand</c>.</b> Those two
/// handlers compose the same stages in the same order, so the temptation is real. They also write
/// <c>Status</c> and <c>Stage</c> themselves, which would leave two layers writing the same
/// columns for one run, and they authorise against <c>ICallerContext</c> — a check a worker can
/// only satisfy by asserting a permission it invented for itself. One writer of the job's state
/// is worth the duplicated call sequence.
/// </para>
/// <para>
/// <b>The three try blocks are the feature.</b> Each stage is wrapped separately so a thrown
/// exception can be attributed before it is recorded. The boundaries are exactly where the
/// runner can honestly place them — see <see cref="ScanPipelineStage"/> for why there are three
/// rather than eight.
/// </para>
/// <para>
/// <b>Nothing here writes to the knowledge corpus.</b> The only corpus-facing call in the whole
/// sequence is inside the audit block, where <c>ThinSlicePipeline</c> asks
/// <c>IKnowledgeRetriever</c> to <em>read</em>. There is no ingestion, indexing or upsert path on
/// this side of the system at all: <c>IKnowledgeSearch</c> exposes only <c>ExactAsync</c> and
/// <c>SearchAsync</c>, and <c>IQueryEmbedder.EmbedAsync</c> embeds query text only. Pipeline A
/// owns writing the corpus and lives in another repository. See the SEC-46 test that asserts it.
/// </para>
/// </remarks>
public sealed class ScanPipelineRunner(
    IUnitOfWork unitOfWork,
    NormalizationPipeline normalization,
    IngressRedactionGate gate,
    NormalizedFindingWriter findingWriter,
    GraphStagePipeline graphStage,
    ThinSlicePipeline thinSlice,
    ChainOutcomeWriter chainOutcomeWriter,
    ILogger<ScanPipelineRunner> logger)
{
    /// <summary>
    /// Drives one job from claimed to completed or failed.
    /// </summary>
    /// <param name="scanJobId">A job this worker has already claimed — status is <c>Running</c>.</param>
    /// <param name="tenantId">
    /// Its tenant, from the claim. The scope has already assumed it, so every query below is
    /// filtered to it; it is passed on explicitly because the stage services take it as an
    /// argument rather than resolving it themselves.
    /// </param>
    public async Task<ScanRunOutcome> RunAsync(Guid scanJobId, Guid tenantId, CancellationToken ct = default)
    {
        var job = await unitOfWork.Repository<ScanJob>()
            .GetTableAsTracked()
            .FirstOrDefaultAsync(j => j.Id == scanJobId, ct);

        if (job is null)
        {
            // The claim just updated this row, so failing to read it back means the scope's
            // tenant does not match the job's — the one bug AssumableCallerContext exists to
            // prevent. Said explicitly, because the symptom otherwise is an empty scan that
            // reports success.
            var reason =
                $"scan job {scanJobId} was claimed but cannot be read back for tenant {tenantId}; "
                + "the pipeline scope did not assume the claimed job's tenant";

            logger.LogError("{Reason}", reason);
            return ScanRunOutcome.Failure(scanJobId, ScanPipelineStage.Normalize, reason);
        }

        var bundle = (await unitOfWork.Repository<ScanBundle>()
            .GetWhereAsync(b => b.ScanJobId == job.Id)).FirstOrDefault();

        if (bundle is null || string.IsNullOrWhiteSpace(bundle.StorageLocator))
        {
            const string reason = "this job has no stored bundle to process";
            await RecordFailureAsync(job, ScanPipelineStage.Normalize, reason);
            return ScanRunOutcome.Failure(scanJobId, ScanPipelineStage.Normalize, reason);
        }

        if (job.BundlePurged)
        {
            const string reason = "this job's bundle has already been purged";
            await RecordFailureAsync(job, ScanPipelineStage.Normalize, reason);
            return ScanRunOutcome.Failure(scanJobId, ScanPipelineStage.Normalize, reason);
        }

        logger.LogInformation(
            "Pipeline B starting for scan job {ScanJobId} (tenant {TenantId}, commit {CommitSha})",
            job.Id, tenantId, job.CommitSha);

        // ---- Stage 1: normalize, with the SEC-33 ingress gate inside it --------------------
        IReadOnlyList<Finding> findings;

        try
        {
            findings = await NormalizeAsync(job, bundle, tenantId, ct);
        }
        catch (Exception ex)
        {
            return await FailAsync(job, ScanPipelineStage.Normalize, ex);
        }

        // ---- Stage 2: graph and candidate chains --------------------------------------------
        GraphStageResult graph;

        try
        {
            graph = await GraphAsync(job, bundle, findings, tenantId, ct);
        }
        catch (Exception ex)
        {
            return await FailAsync(job, ScanPipelineStage.Graph, ex, findings.Count);
        }

        // ---- Stage 3: retrieve, debate, report, retention ------------------------------------
        try
        {
            await AuditAsync(job, tenantId, ct);
        }
        catch (Exception ex)
        {
            return await FailAsync(job, ScanPipelineStage.Audit, ex, findings.Count, graph.Chains.Count);
        }

        await CompleteAsync(job);

        logger.LogInformation(
            "Pipeline B completed for scan job {ScanJobId}: {Findings} finding(s), "
            + "{Chains} candidate chain(s)", job.Id, findings.Count, graph.Chains.Count);

        return ScanRunOutcome.Success(job.Id, findings.Count, graph.Chains.Count);
    }

    /// <summary>
    /// SARIF/JSON to one unified, redacted, persisted finding set.
    /// </summary>
    /// <remarks>
    /// The gate runs after the normalizer and not before it, despite "ingress redaction" being
    /// named first in the ticket: it redacts <em>findings</em>, which do not exist as text until
    /// the normalizer has read them out of the bundle. Its placement is still the security-correct
    /// one — after the findings exist, before anything has persisted them, rendered them into a
    /// brief, or sent them anywhere. The normalizer's own list is deliberately not used again
    /// afterwards; the gate's output is what continues.
    /// </remarks>
    private async Task<IReadOnlyList<Finding>> NormalizeAsync(
        ScanJob job, ScanBundle bundle, Guid tenantId, CancellationToken ct)
    {
        logger.LogInformation(
            "Stage {Stage} started for scan job {ScanJobId}", ScanPipelineStage.Normalize, job.Id);

        var normalized = await normalization.NormalizeAsync(bundle.StorageLocator, tenantId, job.Id, ct);
        var gated = await gate.ApplyAsync(bundle.StorageLocator, normalized, tenantId, job.Id, ct);
        var findings = gated.Findings;

        await MarkRedactionAppliedAsync(bundle);

        // Before the graph, not after: a chain hop's finding id is a foreign key, so the findings
        // have to be rows by the time the chains are written.
        await findingWriter.WriteAsync(findings, job.Id, ct);

        await AdvanceStageAsync(job, ScanStage.Normalize);

        logger.LogInformation(
            "Stage {Stage} completed for scan job {ScanJobId}: {Findings} finding(s), "
            + "{Redacted} message(s) redacted, {Secrets} hardcoded secret(s)",
            ScanPipelineStage.Normalize, job.Id, findings.Count,
            gated.MessagesRedacted, gated.ArtifactSecrets);

        return findings;
    }

    /// <summary>The resource graph, and SEC-20's bounded traversal over it.</summary>
    private async Task<GraphStageResult> GraphAsync(
        ScanJob job, ScanBundle bundle, IReadOnlyList<Finding> findings, Guid tenantId, CancellationToken ct)
    {
        logger.LogInformation(
            "Stage {Stage} started for scan job {ScanJobId}", ScanPipelineStage.Graph, job.Id);

        var result = await graphStage.RunAsync(bundle.StorageLocator, findings, tenantId, job.Id, ct);

        await AdvanceStageAsync(job, ScanStage.Graph);

        logger.LogInformation(
            "Stage {Stage} completed for scan job {ScanJobId}: {Terraform} terraform file(s), "
            + "{Locks} lock file(s), {Dockerfiles} dockerfile(s), {Chains} candidate chain(s)",
            ScanPipelineStage.Graph, job.Id, result.TerraformFileCount, result.LockFileCount,
            result.DockerfileCount, result.Chains.Count);

        return result;
    }

    /// <summary>
    /// Retrieval, debate, report and retention — the one call into SEC-45's composer.
    /// </summary>
    /// <remarks>
    /// The graph stage's output is read back out of the database rather than passed along in
    /// memory, matching what <c>RunAuditStageCommandHandler</c> does and for the same reason: the
    /// graph the agents reason over should be the one in the rows, so a run cannot agree with
    /// itself while disagreeing with what was persisted. Candidate chains are left null on
    /// purpose — the persisted <c>Chain</c> rows are the graph stage's record, and rebuilding
    /// <c>CandidateChain</c> objects from them here would repeat SEC-20's traversal with no new
    /// information.
    /// </remarks>
    private async Task AuditAsync(ScanJob job, Guid tenantId, CancellationToken ct)
    {
        logger.LogInformation(
            "Stage {Stage} started for scan job {ScanJobId}", ScanPipelineStage.Audit, job.Id);

        var findings = await unitOfWork.Repository<Finding>()
            .GetTableAsNotTracked().Where(f => f.ScanJobId == job.Id).ToListAsync(ct);

        var nodes = await unitOfWork.Repository<GraphNode>()
            .GetTableAsNotTracked().Where(n => n.ScanJobId == job.Id).ToListAsync(ct);

        var edges = await unitOfWork.Repository<GraphEdge>()
            .GetTableAsNotTracked().Where(e => e.ScanJobId == job.Id).ToListAsync(ct);

        if (findings.Count == 0)
        {
            // Not merely unusual. Findings were written a moment ago in this same run, so reading
            // none back means the tenant filter is hiding them — and a debate over zero findings
            // produces a clean-looking report. Refusing is the whole point.
            throw new InvalidOperationException(
                $"scan job {job.Id} has no readable findings at the audit stage, though the "
                + "normalize stage wrote them in this run; the pipeline scope's tenant does not "
                + "match the job's");
        }

        var result = await thinSlice.RunAsync(findings, tenantId, job.Id, nodes, edges, candidates: null, ct);

        // SEC-28: without this the graph stage's chain rows stay "candidate" forever, and a reader
        // could never tell a chain the debate validated from one nobody has looked at.
        await chainOutcomeWriter.ApplyAsync(job.Id, result.Audit, ct);

        logger.LogInformation(
            "Stage {Stage} completed for scan job {ScanJobId}: debate {Outcome} in {Rounds} "
            + "round(s), {Citations} citation(s), report {Fate}",
            ScanPipelineStage.Audit, job.Id, result.Audit.Outcome, result.Audit.Rounds,
            result.Report.Citations.Count,
            result.Retention.ReportRetained ? "retained" : "discarded");
    }

    /// <summary>Records that the ingress gate ran (SEC-33), whether or not it found anything.</summary>
    private async Task MarkRedactionAppliedAsync(ScanBundle bundle)
    {
        if (bundle.IngressRedactionApplied) return;

        bundle.IngressRedactionApplied = true;
        await unitOfWork.Repository<ScanBundle>().UpdateAsync(bundle);
        await unitOfWork.CompleteAsync();
    }

    /// <summary>Moves the job's milestone forward mid-run. Status stays <c>Running</c>.</summary>
    private async Task AdvanceStageAsync(ScanJob job, ScanStage stage)
    {
        job.Stage = stage;
        await unitOfWork.CompleteAsync();
    }

    /// <summary>The one place a run is declared successful.</summary>
    private async Task CompleteAsync(ScanJob job)
    {
        job.Stage = ScanStage.Report;
        job.Status = ScanStatus.Completed;
        job.CompletedAt = DateTime.UtcNow;
        job.FailureReason = null;

        await unitOfWork.CompleteAsync();
    }

    /// <summary>Logs the failure, records it on the job, and shapes the outcome.</summary>
    private async Task<ScanRunOutcome> FailAsync(
        ScanJob job, ScanPipelineStage stage, Exception failure, int findings = 0, int chains = 0)
    {
        logger.LogError(
            failure, "Stage {Stage} failed for scan job {ScanJobId}: {Reason}",
            stage, job.Id, failure.Message);

        await RecordFailureAsync(job, stage, failure.Message);

        return ScanRunOutcome.Failure(job.Id, stage, failure.Message, findings, chains);
    }

    /// <summary>
    /// Writes the failure onto the job without letting a second failure escape.
    /// </summary>
    /// <remarks>
    /// Pending changes are discarded first. If the stage died <em>because</em> the database
    /// rejected them — a common case — they are still in the unit of work, and saving the status
    /// on top would resend the rejected batch and throw the same exception out of the failure
    /// handler. The outer catch covers the rest: a run whose failure could not be recorded is
    /// worth a log line, not a crashed worker.
    /// </remarks>
    private async Task RecordFailureAsync(ScanJob job, ScanPipelineStage stage, string reason)
    {
        try
        {
            unitOfWork.DiscardChanges();

            var tracked = await unitOfWork.Repository<ScanJob>()
                .GetTableAsTracked()
                .FirstOrDefaultAsync(j => j.Id == job.Id);

            if (tracked is null)
            {
                logger.LogError(
                    "Could not re-read scan job {ScanJobId} to record its {Stage} failure",
                    job.Id, stage);

                return;
            }

            tracked.Status = ScanStatus.Failed;
            tracked.CompletedAt = DateTime.UtcNow;

            // TODO(SEC-46 checkpoint d): the stage also goes in its own column once the migration
            // lands. Prefixed here so the information exists on the row in the meantime.
            tracked.FailureReason = $"[{stage}] {reason}";

            await unitOfWork.CompleteAsync();
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex, "Could not record the {Stage} failure on scan job {ScanJobId}", stage, job.Id);
        }
    }
}

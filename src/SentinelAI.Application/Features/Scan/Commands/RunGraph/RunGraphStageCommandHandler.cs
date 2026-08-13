using System.Net;
using MediatR;
using Microsoft.Extensions.Logging;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Commands.RunGraph;

/// <summary>
/// Normalize (SEC-14/15/16) → graph (SEC-17/18/19) → candidate chains (SEC-20), for one job.
/// </summary>
public class RunGraphStageCommandHandler(
    IUnitOfWork unitOfWork,
    ICallerContext caller,
    NormalizationPipeline normalization,
    IngressRedactionGate gate,
    NormalizedFindingWriter findingWriter,
    GraphStagePipeline graphStage,
    ILogger<RunGraphStageCommandHandler> logger)
    : IRequestHandler<RunGraphStageCommand, Response>
{
    public async Task<Response> Handle(RunGraphStageCommand request, CancellationToken ct)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        // Running the pipeline writes graph and chain rows, so it is a write, not a read.
        if (!caller.HasScope(AuthScopes.ScanWrite))
            return await Response.FailureAsync($"the '{AuthScopes.ScanWrite}' scope is required", HttpStatusCode.Forbidden);

        var tenantId = caller.TenantId.Value;

        // A job belonging to another tenant looks identical to one that does not exist (SEC-32).
        var job = await unitOfWork.ScanJobRepository.GetForTenantAsync(request.ScanJobId, tenantId, ct);
        if (job is null)
            return await Response.FailureAsync($"no scan job '{request.ScanJobId}'", HttpStatusCode.NotFound);

        if (job.BundlePurged)
            return await Response.FailureAsync("this job's bundle has been purged", HttpStatusCode.Gone);

        var bundle = (await unitOfWork.Repository<ScanBundle>()
            .GetWhereAsync(b => b.ScanJobId == job.Id)).FirstOrDefault();

        if (bundle is null || string.IsNullOrWhiteSpace(bundle.StorageLocator))
            return await Response.FailureAsync("this job has no stored bundle", HttpStatusCode.Conflict);

        try
        {
            var normalized = await normalization.NormalizeAsync(bundle.StorageLocator, tenantId, job.Id, ct);

            // SEC-33: the gate sits exactly here. The findings now exist as text, and nothing has
            // yet persisted them, rendered them into a brief, or sent them anywhere. Its output —
            // redacted findings plus any hardcoded secret it raised — is what continues; the
            // normalizer's list is deliberately not used again below.
            var gated = await gate.ApplyAsync(bundle.StorageLocator, normalized, tenantId, job.Id, ct);
            var findings = gated.Findings;

            await MarkRedactionAppliedAsync(bundle);

            // Before the graph, not after: a chain hop's finding_id is a foreign key, so the
            // findings have to be rows by the time the chains are written.
            await findingWriter.WriteAsync(findings, job.Id, ct);

            var result = await graphStage.RunAsync(bundle.StorageLocator, findings, tenantId, job.Id, ct);

            await AdvanceStageAsync(job, ScanStage.Graph, failure: null);

            return await Response.SuccessAsync(
                RunGraphStageResponse.From(job.Id, findings, gated, result),
                "graph stage complete",
                HttpStatusCode.OK);
        }
        catch (Exception ex)
        {
            // The stage is synchronous and manually triggered, so the caller is the one who needs
            // to see the failure — but the job row is what a later reader will look at, so it
            // records the reason too rather than staying silently at its old stage.
            logger.LogError(ex, "Graph stage failed for scan job {ScanJobId}", job.Id);
            await RecordFailureAsync(job, ex);

            return await Response.FailureAsync(
                $"graph stage failed: {ex.Message}", HttpStatusCode.InternalServerError);
        }
    }

    /// <summary>
    /// Writes the failure onto the job without letting a second failure escape.
    /// </summary>
    /// <remarks>
    /// The changes the stage had queued are dropped first. If the stage died <em>because</em> the
    /// database rejected them — the usual case — they are still sitting in the unit of work, and
    /// saving the status on top of them would resend the rejected batch and throw the same
    /// exception out of the catch block, past this handler, to the caller as an unhandled error.
    /// The wrapping catch covers the rest: the caller is owed the real reason for the failure,
    /// which matters more than the bookkeeping succeeding.
    /// </remarks>
    private async Task RecordFailureAsync(ScanJob job, Exception failure)
    {
        try
        {
            unitOfWork.DiscardChanges();
            await AdvanceStageAsync(job, job.Stage, failure.Message);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Could not record the graph-stage failure on scan job {ScanJobId}", job.Id);
        }
    }

    /// <summary>
    /// Records on the bundle that the ingress gate ran (SEC-33).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set whenever the gate completed, not only when it found something. The column is
    /// documented as "proof the backend redacted before any LLM call", and the auditable claim
    /// is that the check happened — a clean bundle and an unchecked one are not the same fact,
    /// and <c>false</c> has to keep meaning "nobody looked".
    /// </para>
    /// <para>
    /// Written before the graph stage rather than after it, so a job that dies in traversal
    /// still carries the truth about what was scanned.
    /// </para>
    /// </remarks>
    private async Task MarkRedactionAppliedAsync(ScanBundle bundle)
    {
        if (bundle.IngressRedactionApplied) return;

        bundle.IngressRedactionApplied = true;
        await unitOfWork.Repository<ScanBundle>().UpdateAsync(bundle);
        await unitOfWork.CompleteAsync();
    }

    /// <summary>
    /// Records where the job got to. The repository reads jobs untracked, so this attaches the
    /// row explicitly rather than relying on change tracking.
    /// </summary>
    private async Task AdvanceStageAsync(ScanJob job, ScanStage stage, string? failure)
    {
        job.Stage = stage;
        job.Status = failure is null ? ScanStatus.Running : ScanStatus.Failed;
        job.FailureReason = failure;

        await unitOfWork.Repository<ScanJob>().UpdateAsync(job);
        await unitOfWork.CompleteAsync();
    }
}

/// <summary>
/// What the run produced, flattened for the wire. Chains carry their full node path because the
/// point of triggering this by hand is to look at them.
/// </summary>
public sealed record RunGraphStageResponse
{
    public required string ScanJobId { get; init; }
    public required int Findings { get; init; }

    /// <summary>SEC-33: how many finding messages had a credential removed at ingress.</summary>
    public required int MessagesRedacted { get; init; }

    /// <summary>SEC-33: hardcoded credentials found in the bundle's own artifacts.</summary>
    public required int HardcodedSecrets { get; init; }
    public required int TerraformFiles { get; init; }
    public required int LockFiles { get; init; }
    public required int Dockerfiles { get; init; }
    public required int CandidateChains { get; init; }
    public required IReadOnlyList<ChainView> Chains { get; init; }

    /// <summary>
    /// Every candidate is a path that exists in the graph, not an attack that was proven. Sent on
    /// the wire so a caller cannot render this as a verdict (AID-01 §7).
    /// </summary>
    public string Disclaimer =>
        "Candidate chains only: deterministically generated from real graph edges. "
        + "Nothing here is an asserted or validated attack path — that is the debate's job.";

    public static RunGraphStageResponse From(
        Guid scanJobId,
        IReadOnlyList<Finding> findings,
        IngressRedactionResult redaction,
        GraphStageResult result) => new()
        {
            ScanJobId = scanJobId.ToString(),
            Findings = findings.Count,
            MessagesRedacted = redaction.MessagesRedacted,
            HardcodedSecrets = redaction.ArtifactSecrets,
            TerraformFiles = result.TerraformFileCount,
            LockFiles = result.LockFileCount,
            Dockerfiles = result.DockerfileCount,
            CandidateChains = result.Chains.Count,
            Chains = [.. result.Chains.Select(ChainView.From)],
        };

    /// <param name="Path">The node keys in order, so the chain is readable without a second call.</param>
    /// <param name="MinConfidence">The weakest join anywhere on the path (AID-01 §3.3).</param>
    public sealed record ChainView(
        int Priority,
        int HopCount,
        string MinConfidence,
        int MaxSeverity,
        IReadOnlyList<string> Path,
        IReadOnlyList<HopView> Hops)
    {
        public static ChainView From(CandidateChain chain) => new(
            chain.Priority,
            chain.HopCount,
            chain.MinConfidence.ToString(),
            chain.MaxSeverity,
            [.. chain.Hops.Select(h => h.Node.NodeKey)],
            [.. chain.Hops.Select(HopView.From)]);
    }

    /// <param name="Relation">Null on the seed hop, which arrived from nowhere.</param>
    /// <param name="Findings">What was reported on this node. Empty is normal.</param>
    public sealed record HopView(
        int Order,
        string NodeKey,
        string Layer,
        string Tactic,
        string? Relation,
        string? Confidence,
        IReadOnlyList<string> Findings)
    {
        public static HopView From(CandidateHop hop) => new(
            hop.Order,
            hop.Node.NodeKey,
            hop.Node.Layer.ToString(),
            hop.Tactic.ToString(),
            hop.EdgeFromPrevious?.Relation,
            hop.EdgeFromPrevious?.Confidence.ToString(),
            [.. hop.Findings.Select(f => $"{f.SourceTool} sev{f.Severity} {f.CweId ?? f.CveId ?? f.CheckId}")]);
    }
}

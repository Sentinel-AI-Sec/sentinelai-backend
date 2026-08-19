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
    ScanBriefRenderer briefRenderer,
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

            // Read back what was persisted rather than reusing an in-memory copy: the graph the
            // agents will reason over is the one in the rows, and a response built from
            // something else could agree with the pipeline while disagreeing with the database.
            var graph = await ReadGraphAsync(job.Id);
            var brief = briefRenderer.Render(job.Id, findings, graph.Nodes, [], graph.Edges);

            LogGraph(job.Id, graph, brief);

            return await Response.SuccessAsync(
                RunGraphStageResponse.From(job.Id, findings, gated, result, graph, brief.Context),
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

    /// <summary>The graph rows this job persisted, nodes and edges together.</summary>
    private async Task<PersistedGraph> ReadGraphAsync(Guid scanJobId)
    {
        var nodes = (await unitOfWork.Repository<GraphNode>()
            .GetWhereAsync(n => n.ScanJobId == scanJobId)).ToList();

        var edges = (await unitOfWork.Repository<GraphEdge>()
            .GetWhereAsync(e => e.ScanJobId == scanJobId)).ToList();

        return new PersistedGraph(nodes, edges);
    }

    /// <summary>
    /// Logs the graph the agents will be given, in full.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Counts alone cannot answer the question anyone debugging a bad chain actually has, which
    /// is <em>which</em> edges the agents were shown. "68 edges" and "68 edges, none of them
    /// joining the layer you care about" print identically.
    /// </para>
    /// <para>
    /// At <see cref="LogLevel.Debug"/>, because on a large repository this is thousands of lines
    /// and the summary above it is what a normal run wants. It is also on the response, so the
    /// usual way to read it is the HTTP body rather than turning logging up.
    /// </para>
    /// </remarks>
    private void LogGraph(Guid scanJobId, PersistedGraph graph, ScanBrief brief)
    {
        logger.LogInformation(
            "Graph for scan job {ScanJobId}: {Nodes} node(s), {Edges} edge(s), {Hot} hot",
            scanJobId, graph.Nodes.Count, graph.Edges.Count, graph.Nodes.Count(n => n.IsHot));

        if (!logger.IsEnabled(LogLevel.Debug)) return;

        logger.LogDebug(
            "Resource graph handed to the agents for scan job {ScanJobId}:\n{ResourceGraph}",
            scanJobId, brief.Context);
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

/// <summary>The graph rows one scan job persisted.</summary>
public sealed record PersistedGraph(IReadOnlyList<GraphNode> Nodes, IReadOnlyList<GraphEdge> Edges);

/// <param name="Key">Canonical node key — <c>type:identifier</c>, lower-case.</param>
/// <param name="Hot">Decorated by a high-severity finding, so traversal may seed from it.</param>
public sealed record NodeView(string Key, string Type, string Layer, bool Hot)
{
    public static NodeView From(GraphNode node) =>
        new(node.NodeKey, node.NodeType.ToString(), node.Layer.ToString(), node.IsHot);
}

/// <summary>An edge by node key, so it can be read without resolving row ids.</summary>
public sealed record EdgeView(string From, string Relation, string To, string Confidence)
{
    /// <summary>
    /// Skips an edge whose endpoints are not both present. That should be impossible — the
    /// writers persist both together — but a dangling reference on the wire is worse than an
    /// omission, because it reads as a node the caller simply failed to find.
    /// </summary>
    public static IEnumerable<EdgeView> ListFrom(PersistedGraph graph)
    {
        var keyById = graph.Nodes.ToDictionary(n => n.Id, n => n.NodeKey);

        foreach (var edge in graph.Edges)
        {
            if (!keyById.TryGetValue(edge.FromNodeId, out var from) ||
                !keyById.TryGetValue(edge.ToNodeId, out var to))
                continue;

            yield return new EdgeView(from, edge.Relation, to, edge.Confidence.ToString());
        }
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

    /// <summary>Every node the graph stage persisted for this job.</summary>
    public required IReadOnlyList<NodeView> Nodes { get; init; }

    /// <summary>Every edge, by node key rather than by row id, so it reads without a join.</summary>
    public required IReadOnlyList<EdgeView> Edges { get; init; }

    /// <summary>
    /// The resource graph exactly as the agents receive it — the rendered brief text.
    /// </summary>
    /// <remarks>
    /// On the wire because a chain the agents get wrong is almost always a chain they were shown
    /// wrongly, and until this was here there was no way to see what they had been shown short of
    /// attaching a debugger. It is also the fastest way to exercise the agents against a real
    /// graph: paste it into <c>POST /v1/debates</c> as <c>resourceGraph</c> and the debate runs
    /// over this scan's actual nodes and edges.
    /// </remarks>
    public required string ResourceGraph { get; init; }

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
        GraphStageResult result,
        PersistedGraph graph,
        string resourceGraph) => new()
        {
            Nodes = [.. graph.Nodes.Select(NodeView.From)],
            Edges = [.. EdgeView.ListFrom(graph)],
            ResourceGraph = resourceGraph,
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

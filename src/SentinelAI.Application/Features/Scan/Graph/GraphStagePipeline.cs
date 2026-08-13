using System.Text;
using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Graph;

/// <summary>
/// Runs the whole graph stage over one ingested bundle: the four seam writers build the resource
/// graph, then SEC-20 decorates it with this scan's findings and traverses it into candidate
/// chains.
/// </summary>
/// <remarks>
/// <para>
/// Until this class existed, every seam writer was a standalone, fully-tested component that
/// nothing called — the gap <c>docs/Walking_Skeleton.md</c> records as "no scan-job
/// orchestration story anywhere in this codebase". This is that story for the graph half only.
/// It does not normalize (that is <see cref="Normalization.NormalizationPipeline"/>, whose output
/// is this one's input) and it does not debate.
/// </para>
/// <para>
/// <b>It owns Dockerfile-to-project attribution</b>, which no ticket previously did. See
/// <see cref="ProjectPathFor"/> — the answer decides whether the code→infra seam lands on the
/// same Code node the dep→code seam built, and getting it wrong splits the graph in exactly the
/// way SEC-03 exists to prevent.
/// </para>
/// </remarks>
public sealed class GraphStagePipeline(
    IUnitOfWork unitOfWork,
    IBundleStore bundleStore,
    InfraSpineWriter infraSpine,
    DepCodeSeamWriter depCode,
    CodeInfraSeamWriter codeInfra,
    RoleResourceSeamWriter roleResource,
    CandidateChainWriter candidateChains,
    ILogger<GraphStagePipeline> logger)
{
    /// <summary>Everything the runner collects lives under this prefix inside the bundle.</summary>
    private const string GraphInputsPrefix = "graph-inputs/";

    public async Task<GraphStageResult> RunAsync(
        string bundleLocator, IReadOnlyList<Finding> findings, Guid tenantId, Guid scanJobId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleLocator);
        ArgumentNullException.ThrowIfNull(findings);

        var inputs = await ReadGraphInputsAsync(bundleLocator, ct);

        if (inputs.HclFiles.Count == 0 && inputs.LockFiles.Count == 0)
        {
            logger.LogWarning(
                "Bundle for scan job {ScanJobId} carries no Terraform and no lock files; there are "
                + "no edges to build and therefore no chains to find", scanJobId);
        }

        // 0. Whatever a previous run of this job left behind. See ClearPreviousGraphAsync — the
        //    seam writers are additive, so without this the stage builds on top of itself.
        await ClearPreviousGraphAsync(scanJobId);

        // 1. The infra spine (SEC-17). Reads the bundle itself — it is the one writer that needs
        //    the DOT graph, which nothing else looks at.
        await infraSpine.WriteAsync(bundleLocator, tenantId, scanJobId, ct);

        // 2. dep→code, one project per lock file (SEC-18 part A).
        foreach (var (path, content) in inputs.LockFiles)
            await depCode.WriteAsync(path, content, tenantId, scanJobId, ct);

        // 3. code→infra, one call per Dockerfile (SEC-19). Skipped entirely when there is no
        //    Terraform to compare against — the seam would have nothing to join.
        if (inputs.HclFiles.Count > 0)
        {
            foreach (var (path, content) in inputs.Dockerfiles)
            {
                await codeInfra.WriteAsync(
                    ProjectPathFor(path, inputs.LockFiles.Keys), content, inputs.HclFiles, tenantId, scanJobId, ct);
            }
        }

        // 4. role→resource from the IAM policy documents (SEC-18 part B).
        if (inputs.HclFiles.Count > 0)
            await roleResource.WriteAsync(inputs.HclFiles, tenantId, scanJobId, ct);

        // 5. Decorate and traverse (SEC-20).
        var chains = await candidateChains.WriteAsync(bundleLocator, findings, tenantId, scanJobId, ct);

        logger.LogInformation(
            "Graph stage for scan job {ScanJobId}: {Hcl} .tf file(s), {Locks} lock file(s), "
            + "{Dockerfiles} Dockerfile(s) -> {Chains} candidate chain(s)",
            scanJobId, inputs.HclFiles.Count, inputs.LockFiles.Count, inputs.Dockerfiles.Count, chains.Count);

        return new GraphStageResult(
            inputs.HclFiles.Count, inputs.LockFiles.Count, inputs.Dockerfiles.Count, chains);
    }

    /// <summary>
    /// Drops the job's existing graph so this run rebuilds it rather than adding to it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Nodes are upserted on (<c>scan_job_id</c>, <c>node_key</c>) and survive a second run
    /// unchanged, but edges are not: <c>SeamPersistence.UpsertEdgeAsync</c> inserts
    /// unconditionally, so running the stage twice gave every edge a twin. The traverser then
    /// walked each join two ways and produced the same path repeatedly until it hit its candidate
    /// cap — 32 real chains became 200 identical-looking ones, with no error anywhere. That never
    /// showed up before because nothing could run the stage twice; the manual trigger can.
    /// </para>
    /// <para>
    /// Deleting rather than de-duplicating is the honest version of what a re-run means: the
    /// bundle is the source of truth, and a node or edge the current bundle no longer implies has
    /// no business surviving into this scan's graph. The chain rows that referenced these edges
    /// are already gone — <c>NormalizedFindingWriter</c> clears them before this stage runs,
    /// because the same re-run has to replace the findings the hops point at.
    /// </para>
    /// </remarks>
    private async Task ClearPreviousGraphAsync(Guid scanJobId)
    {
        var edges = (await unitOfWork.Repository<GraphEdge>()
            .GetWhereAsync(e => e.ScanJobId == scanJobId)).ToList();

        var nodes = (await unitOfWork.Repository<GraphNode>()
            .GetWhereAsync(n => n.ScanJobId == scanJobId)).ToList();

        if (edges.Count == 0 && nodes.Count == 0) return;

        if (edges.Count > 0) await unitOfWork.Repository<GraphEdge>().DeleteRangeAsync(edges);
        if (nodes.Count > 0) await unitOfWork.Repository<GraphNode>().DeleteRangeAsync(nodes);

        await unitOfWork.CompleteAsync();

        logger.LogInformation(
            "Cleared {Nodes} node(s) and {Edges} edge(s) from a previous graph run of scan job {ScanJobId}",
            nodes.Count, edges.Count, scanJobId);
    }

    /// <summary>
    /// The project path a Dockerfile's Code node should be derived from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A Dockerfile does not say which project it builds, and its location does not always say
    /// either: the reference fixture keeps one Dockerfile at the repository root while its only
    /// project lives in <c>src/OrderApp/</c>. Passing the root path would produce
    /// <c>code:dockerfile</c> while the dep→code seam produced <c>code:orderapp</c> — two nodes
    /// for one project, no edge between them, and a chain that stops at the code layer.
    /// </para>
    /// <para>
    /// The rule, in order: a lock file in the Dockerfile's own directory names the project (the
    /// unambiguous case, and the one a multi-service repository hits); failing that, a repository
    /// with exactly one project has only one answer; failing that, the Dockerfile's own path is
    /// used and the resulting Code node may not join, which is logged rather than guessed
    /// around.
    /// </para>
    /// </remarks>
    private string ProjectPathFor(string dockerfilePath, IEnumerable<string> lockFilePaths)
    {
        var directory = DirectoryOf(dockerfilePath);
        var locks = lockFilePaths.ToList();

        var sibling = locks.FirstOrDefault(
            l => string.Equals(DirectoryOf(l), directory, StringComparison.OrdinalIgnoreCase));

        if (sibling is not null) return dockerfilePath;

        if (locks.Count == 1)
        {
            logger.LogInformation(
                "Dockerfile {Dockerfile} sits outside any project directory; attributing it to the "
                + "bundle's only project, {Project}", dockerfilePath, locks[0]);

            // The lock file's path, not the Dockerfile's: both seams must derive the same Code
            // node, and the lock file is the one that names the project.
            return locks[0];
        }

        logger.LogWarning(
            "Dockerfile {Dockerfile} could not be attributed to a project ({Count} candidates); its "
            + "Code node is derived from its own path and may not join the dep-code seam",
            dockerfilePath, locks.Count);

        return dockerfilePath;
    }

    private static string DirectoryOf(string path)
    {
        var slash = path.LastIndexOf('/');
        return slash < 0 ? string.Empty : path[..slash];
    }

    /// <summary>
    /// Splits the bundle's <c>graph-inputs/</c> into the three shapes the seams consume, with the
    /// prefix stripped so paths are repo-relative again — which is what
    /// <c>ProvisionalCodeNodeResolver</c> reads a project name out of.
    /// </summary>
    private async Task<GraphInputs> ReadGraphInputsAsync(string bundleLocator, CancellationToken ct)
    {
        var hclFiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lockFiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var dockerfiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in await bundleStore.OpenGraphInputsAsync(bundleLocator, ct))
        {
            var path = file.Name.StartsWith(GraphInputsPrefix, StringComparison.OrdinalIgnoreCase)
                ? file.Name[GraphInputsPrefix.Length..]
                : file.Name;

            var name = path[(path.LastIndexOf('/') + 1)..];

            if (name.EndsWith(".tf", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith(".tf.json", StringComparison.OrdinalIgnoreCase))
            {
                hclFiles[path] = Encoding.UTF8.GetString(file.Content);
            }
            else if (name.Equals("packages.lock.json", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("package-lock.json", StringComparison.OrdinalIgnoreCase))
            {
                lockFiles[path] = Encoding.UTF8.GetString(file.Content);
            }
            else if (name.Equals("Dockerfile", StringComparison.OrdinalIgnoreCase) ||
                     name.StartsWith("Dockerfile.", StringComparison.OrdinalIgnoreCase))
            {
                dockerfiles[path] = Encoding.UTF8.GetString(file.Content);
            }

            // Anything else the runner collected (.csproj today) has no seam reading it yet.
        }

        return new GraphInputs(hclFiles, lockFiles, dockerfiles);
    }

    private sealed record GraphInputs(
        Dictionary<string, string> HclFiles,
        Dictionary<string, string> LockFiles,
        Dictionary<string, string> Dockerfiles);
}

/// <summary>What one graph-stage run built.</summary>
/// <param name="Chains">The ranked candidate chains, also persisted as <c>chains</c> rows.</param>
public sealed record GraphStageResult(
    int TerraformFileCount,
    int LockFileCount,
    int DockerfileCount,
    IReadOnlyList<CandidateChain> Chains);

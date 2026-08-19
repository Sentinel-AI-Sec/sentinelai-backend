using System.Text.Json;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-19: builds the code→infra seam — a <c>Code</c> node (see
/// <see cref="ProvisionalCodeNodeResolver"/>), an <c>Image</c> node per distinct image the
/// Terraform side references, and a <c>runs-as</c> edge between them, confidence-scored rather
/// than certain because this whole seam is a name-based heuristic:
/// <list type="bullet">
/// <item><see cref="Confidence.Inferred"/> — the Dockerfile's declared image name and the task
/// definition's (resolved, normalized) image both name the same repository. Not
/// <see cref="Confidence.Certain"/>: matching by name is a convention this reader trusts, not an
/// explicit cross-reference the way a Terraform <c>type.name</c> attribute is.</item>
/// <item><see cref="Confidence.Unresolved"/> — both sides reference an image, but the normalized
/// names disagree. Recorded, not dropped: an unresolved load-bearing join has to stay visible
/// for a human to check, per the ticket.</item>
/// <item>Neither side naming an image at all produces no edge for that task definition — there
/// is nothing to relate, which is different from an unresolved join and not a case the ticket
/// asks this reader to record.</item>
/// </list>
/// <para>
/// Each match also yields a <c>Task</c> node and a <c>code → task</c> <c>deployed-as</c> edge at
/// the same confidence (added for SEC-20 — see <see cref="DeployedAsRelation"/> for why the
/// chain runs through the workload rather than through the image node).
/// </para>
/// </summary>
public sealed class CodeInfraSeamReader : ICodeInfraSeamReader
{
    /// <summary>Code → the image it is built into. What the name match actually compared.</summary>
    private const string Relation = "runs-as";

    /// <summary>
    /// Code → the workload that image is deployed into. Carries the same confidence as the
    /// <c>runs-as</c> edge beside it, because it rests on the same evidence: the name match is
    /// what says this project's code is what runs in that task definition.
    /// </summary>
    /// <remarks>
    /// This is the traversable half of the seam. The image node is the evidence of the join —
    /// the artifact whose name was compared — but an attacker does not move "into an image";
    /// they reach the workload it is deployed as, which is the node the infra spine's
    /// <c>assumes</c> edge continues from. Emitting both keeps the evidence visible without
    /// spending a hop of the 3–4 hop budget (AID-01 §3.2) on a node no scanner reports on and
    /// no attacker stands in.
    /// </remarks>
    private const string DeployedAsRelation = "deployed-as";

    public CodeInfraSeamReadResult Read(CodeInfraSeamInput input, Guid tenantId, Guid scanJobId)
    {
        var codeNodeKey = ProvisionalCodeNodeResolver.ResolveNodeKey(input.ProjectFilePath);
        NodeId.TryParse(codeNodeKey, out _, out var codeIdentifier);
        var codeNode = GraphNode.Create(tenantId, scanJobId, NodeType.Code, codeIdentifier, Layer.Code);
        codeNode.Id = Guid.CreateVersion7();

        var nodesByKey = new Dictionary<string, GraphNode>(StringComparer.Ordinal) { [codeNodeKey] = codeNode };
        var edges = new List<CodeInfraSeamEdge>();

        var dockerImage = DockerfileImageNameExtractor.TryExtractImageName(input.DockerfileText);
        var taskImageRefs = TaskDefinitionImageExtractor.ExtractImageRefsByTaskDefinitionName(input.HclFiles);

        // Nothing to join if either side is silent — see this class's own doc remarks on why
        // that is not the same thing as an unresolved edge.
        if (dockerImage is null || taskImageRefs.Count == 0)
            return new CodeInfraSeamReadResult([.. nodesByKey.Values], edges);

        var normalizedDockerImage = ImageNameNormalizer.Normalize(dockerImage);
        var variables = TerraformVariableResolver.Resolve(input.HclFiles);

        foreach (var (taskDefinitionName, rawImageRef) in taskImageRefs)
        {
            var (resolvedRef, resolvedVariable) = TerraformVariableResolver.Substitute(rawImageRef, variables);
            if (string.IsNullOrWhiteSpace(resolvedRef)) continue;

            var normalizedInfraImage = ImageNameNormalizer.Normalize(resolvedRef);
            var imageNodeKey = NodeId.For(NodeType.Image, normalizedInfraImage);

            if (!nodesByKey.TryGetValue(imageNodeKey, out var imageNode))
            {
                imageNode = GraphNode.Create(tenantId, scanJobId, NodeType.Image, normalizedInfraImage, Layer.Infra);
                imageNode.Id = Guid.CreateVersion7();
                imageNode.Attrs = JsonSerializer.Serialize(new
                {
                    dockerfileImageRef = dockerImage,
                    taskDefinitionImageRef = resolvedRef,
                });
                nodesByKey[imageNodeKey] = imageNode;
            }

            // Extension point (not built yet, per the ticket): a second signal — a matching ECS
            // container *name* between the task definition and a build-side annotation, or an
            // explicit "this Dockerfile builds this task definition's image" annotation file —
            // could raise a name-only match from Inferred toward Certain. Nothing here reads
            // such a signal today; adding one is a new branch in the confidence expression
            // below, not a change to this seam's shape.
            var confidence = normalizedDockerImage == normalizedInfraImage ? Confidence.Inferred : Confidence.Unresolved;

            edges.Add(new CodeInfraSeamEdge(codeNodeKey, imageNodeKey, Relation, confidence, resolvedVariable));

            // The workload the image is deployed into. Its node key is built from the task
            // definition's Terraform resource name, which is the same string
            // TerraformInfraSpineReader canonicalizes — that string equality is the whole join
            // between this seam and the infra spine, and getting it wrong is the island bug.
            var taskNodeKey = NodeId.For(NodeType.Task, taskDefinitionName);
            if (!nodesByKey.ContainsKey(taskNodeKey))
            {
                var taskNode = GraphNode.Create(tenantId, scanJobId, NodeType.Task, taskDefinitionName, Layer.Infra);
                taskNode.Id = Guid.CreateVersion7();
                nodesByKey[taskNodeKey] = taskNode;
            }

            edges.Add(new CodeInfraSeamEdge(
                codeNodeKey, taskNodeKey, DeployedAsRelation, confidence, resolvedVariable));
        }

        return new CodeInfraSeamReadResult([.. nodesByKey.Values], edges);
    }
}

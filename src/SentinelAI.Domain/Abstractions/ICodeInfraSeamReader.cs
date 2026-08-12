using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Abstractions;

/// <summary>
/// Turns a Dockerfile's declared image identity and a Terraform task definition's container
/// image field into the code→infra seam of the resource graph (SEC-19): a <c>Code</c> node, an
/// <c>Image</c> node, and the edge between them. Fragile by design — this is a best-effort
/// name match, not an explicit reference the way <see cref="IRoleResourceSeamReader"/>'s policy
/// grants are — so every edge carries its own <see cref="Confidence"/> rather than the fixed
/// <c>Certain</c> the other two seam readers use.
/// </summary>
public interface ICodeInfraSeamReader
{
    CodeInfraSeamReadResult Read(CodeInfraSeamInput input, Guid tenantId, Guid scanJobId);
}

/// <param name="ProjectFilePath">Bundle-relative path to the Dockerfile, e.g.
/// <c>src/OrderService/Dockerfile</c> — used the same way <see cref="DepCodeSeamInput.ProjectFilePath"/>
/// is, to derive the project's provisional Code node.</param>
/// <param name="DockerfileText">The raw Dockerfile content.</param>
/// <param name="HclFiles">Bundle-root-relative filename to its decoded <c>.tf</c> text content —
/// searched for <c>aws_ecs_task_definition</c> blocks and the <c>variable</c>/<c>locals</c>
/// blocks needed to resolve their image field.</param>
public sealed record CodeInfraSeamInput(
    string ProjectFilePath, string DockerfileText, IReadOnlyDictionary<string, string> HclFiles);

/// <summary>
/// One code→infra edge.
/// </summary>
/// <param name="Confidence">
/// <see cref="Enums.Confidence.Inferred"/> when the normalized Dockerfile and task-definition
/// image names match exactly; <see cref="Enums.Confidence.Unresolved"/> when both sides name an
/// image but the normalized names don't agree — recorded, not dropped, so an unresolved
/// load-bearing join stays visible for human review instead of silently vanishing.
/// </param>
/// <param name="ResolvedVariable">
/// True when the task definition's image field was a Terraform variable/local reference
/// (<c>${var.x}</c>/<c>${local.x}</c>) that this reader had to resolve before it could compare
/// names, rather than a literal string already. Exists for the same reason
/// <see cref="InfraSpineEdge.OrientedAttackDir"/> does: so a test can assert the resolution path
/// actually ran on the cases that need it, instead of trusting that a passing match happened to
/// not need it.
/// </param>
public sealed record CodeInfraSeamEdge(
    string FromNodeKey, string ToNodeKey, string Relation, Confidence Confidence, bool ResolvedVariable);

/// <summary>The result of one <see cref="ICodeInfraSeamReader.Read"/> call.</summary>
/// <param name="Nodes">The project's <c>Code</c> node plus one <c>Image</c> node per distinct
/// normalized image name this reader found evidence of (Dockerfile side, task-definition side,
/// or both).</param>
public sealed record CodeInfraSeamReadResult(IReadOnlyList<GraphNode> Nodes, IReadOnlyList<CodeInfraSeamEdge> Edges);

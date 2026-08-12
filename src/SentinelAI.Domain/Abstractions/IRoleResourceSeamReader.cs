using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Abstractions;

/// <summary>
/// Turns a bundle's Terraform IAM policy statements into the role→resource seam of the resource
/// graph (SEC-18 part B): a <c>can-access</c> edge from an <c>IamRole</c> node to every
/// <c>Resource</c> node its policies grant access to. Covers all three IAM policy shapes
/// Terraform allows — inline policies inside <c>aws_iam_role</c>, standalone
/// <c>aws_iam_role_policy</c> resources, and managed-policy attachments
/// (<c>aws_iam_role_policy_attachment</c>) — because missing any one of them reproduces this
/// project's "zero-chains" failure mode from a role→resource edge that silently never got drawn.
/// </summary>
public interface IRoleResourceSeamReader
{
    /// <summary>
    /// Reads the role→resource grants out of a bundle's raw <c>.tf</c> sources. HCL only — the
    /// Terraform DOT graph carries no policy-statement text, only resource structure — so unlike
    /// <see cref="IInfraSpineReader"/> there is no DOT-vs-HCL fallback choice to make here.
    /// </summary>
    RoleResourceSeamReadResult Read(RoleResourceSeamInput input, Guid tenantId, Guid scanJobId);
}

/// <param name="HclFiles">Bundle-root-relative filename to its decoded <c>.tf</c> text content —
/// the same shape <see cref="InfraSpineInput.HclFiles"/> uses, so a caller that already has one
/// bundle's graph inputs open can hand the same dictionary to both readers.</param>
public sealed record RoleResourceSeamInput(IReadOnlyDictionary<string, string> HclFiles);

/// <summary>
/// One role→resource edge. Always <c>can-access</c>, always certain — an IAM policy statement is
/// an explicit grant, not a heuristic.
/// </summary>
/// <param name="Widened">
/// True when this edge exists because a policy statement used a wildcard (<c>Resource: "*"</c>,
/// an action wildcard like <c>s3:*</c>, or a managed policy whose exact grant this reader could
/// not resolve to one ARN) and was widened to every known <c>Resource</c>-typed node rather than
/// dropped. Exists for the same reason <see cref="InfraSpineEdge.OrientedAttackDir"/> does — so
/// a caller or test can assert the widening path actually ran instead of trusting that a
/// wildcard policy produced <em>an</em> edge by coincidence.
/// </param>
public sealed record RoleResourceSeamEdge(string FromNodeKey, string ToNodeKey, string Relation, bool Widened);

/// <summary>The result of one <see cref="IRoleResourceSeamReader.Read"/> call.</summary>
/// <param name="Nodes">
/// The <c>IamRole</c> nodes these edges originate from. Deliberately re-derived here rather than
/// assumed to already exist from <see cref="IInfraSpineReader"/>: this reader is standalone and
/// independently testable, and the (scan_job_id, node_key) upsert at persistence time is what
/// merges it back with whatever the infra spine already produced for the same role.
/// </param>
public sealed record RoleResourceSeamReadResult(IReadOnlyList<GraphNode> Nodes, IReadOnlyList<RoleResourceSeamEdge> Edges);

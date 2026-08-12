namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-17 step 2: reverses raw Terraform edges from build-order direction into attack
/// direction. Terraform's <c>-&gt;</c> means "the source depends on the target, so the target
/// must exist first" — e.g. an ECS task definition points at the IAM role it assumes, because
/// the task can't be created before the role. An attacker who has compromised that role moves
/// the opposite way: from the role to the task it's attached to. Every edge this produces has
/// therefore swapped <c>From</c>/<c>To</c> relative to its input, which is exactly what
/// <see cref="OrientedTfEdge.OrientedAttackDir"/> being unconditionally true asserts happened.
/// </summary>
/// <remarks>
/// Kept as its own class, not folded into <see cref="TerraformDotParser"/>, on purpose: this is
/// called out in the ticket as the highest-risk logic in the whole feature — get the direction
/// backwards and every downstream chain-detection stage silently finds zero chains, with no
/// error anywhere (the "zero-chains failure mode"). Isolating it means it can carry its own
/// narrow regression test (<c>AttackDirectionOrienterTests.Reversal_is_not_accidentally_skipped</c>)
/// that fails loudly the moment anyone "simplifies" this away.
/// </remarks>
internal static class AttackDirectionOrienter
{
    public static IReadOnlyList<OrientedTfEdge> Reverse(IReadOnlyList<TerraformRawEdge> buildOrderEdges) =>
        buildOrderEdges
            .Select(e => new OrientedTfEdge(FromAddress: e.ToAddress, ToAddress: e.FromAddress, OrientedAttackDir: true))
            .ToList();
}

/// <summary>
/// An edge already reversed into attack direction: <see cref="FromAddress"/> is where an
/// attacker starts, <see cref="ToAddress"/> is where the edge lets them move to.
/// <see cref="OrientedAttackDir"/> is always true for anything this class produces — it exists
/// so a caller (or a test) can assert the reversal actually ran rather than trusting the field
/// name alone.
/// </summary>
internal sealed record OrientedTfEdge(string FromAddress, string ToAddress, bool OrientedAttackDir);

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-17 step 2: reverses raw Terraform edges from build-order direction into attack
/// direction. Terraform's <c>-&gt;</c> means "the source depends on the target, so the target
/// must exist first" — e.g. an ECS service points at the task definition it runs, because the
/// service can't be created before the task exists. An attacker moves the opposite way: from the
/// task they are executing in, on to the service that fronts it. Every edge this produces has
/// therefore swapped <c>From</c>/<c>To</c> relative to its input, which is exactly what
/// <see cref="OrientedTfEdge.OrientedAttackDir"/> being unconditionally true asserts happened.
/// </summary>
/// <remarks>
/// <para>
/// Kept as its own class, not folded into <see cref="TerraformDotParser"/>, on purpose: this is
/// called out in the ticket as the highest-risk logic in the whole feature — get the direction
/// backwards and every downstream chain-detection stage silently finds zero chains, with no
/// error anywhere (the "zero-chains failure mode"). Isolating it means it can carry its own
/// narrow regression test (<c>AttackDirectionOrienterTests.Reversal_is_not_accidentally_skipped</c>)
/// that fails loudly the moment anyone "simplifies" this away.
/// </para>
/// <para>
/// <b>Blanket reversal is right for the resource pairs this was written against, and wrong for
/// one of them.</b> A task definition's dependency on the IAM role it assumes reverses to
/// <c>role → task</c>, and holding a role does not put an attacker inside a task — the move
/// runs the other way. That case is not special-cased here, because narrowing this reversal is
/// the exact edit the regression test above exists to stop. It is settled one level up:
/// <see cref="TerraformInfraSpineReader"/> emits the <c>task → role</c> <c>assumes</c> edge from
/// the reference that creates it and drops this class's mirror image of it. Nothing else about
/// this class's output is filtered.
/// </para>
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

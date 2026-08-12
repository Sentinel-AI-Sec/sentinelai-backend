using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>
/// SEC-17 step 2 — the highest-risk logic in the ticket. Get this backwards and every
/// downstream chain-detection stage silently finds zero chains, with no error anywhere (the
/// "zero-chains failure mode"), which is why <see cref="Reversal_is_not_accidentally_skipped"/>
/// exists as a standing regression guard rather than trusting the happy-path tests alone.
/// </summary>
public class AttackDirectionOrienterTests
{
    [Fact]
    public void Reverses_build_order_into_attack_direction()
    {
        // Terraform's own direction: the task depends on the role (task -> role), because the
        // role must exist before the task can assume it.
        var buildOrder = new[] { new TerraformRawEdge("aws_ecs_task_definition.order_task", "aws_iam_role.order_task_role") };

        var oriented = AttackDirectionOrienter.Reverse(buildOrder);

        var edge = Assert.Single(oriented);
        // An attacker who compromises the role moves TO the task — the opposite direction.
        Assert.Equal("aws_iam_role.order_task_role", edge.FromAddress);
        Assert.Equal("aws_ecs_task_definition.order_task", edge.ToAddress);
    }

    [Fact]
    public void Sets_the_oriented_flag_on_every_edge_it_produces()
    {
        var buildOrder = new[]
        {
            new TerraformRawEdge("a", "b"),
            new TerraformRawEdge("b", "c"),
        };

        var oriented = AttackDirectionOrienter.Reverse(buildOrder);

        Assert.All(oriented, e => Assert.True(e.OrientedAttackDir));
    }

    /// <summary>
    /// The zero-chains guard (ticket step 5): feed in an edge still pointing in Terraform's
    /// original build-order direction (as if the reversal step had been silently skipped or
    /// broken) and prove the pipeline's orientation logic actually flips it, rather than
    /// passing it through unchanged. If a future edit to <see cref="AttackDirectionOrienter"/>
    /// ever turns <c>Reverse</c> into an identity function, this assertion fails — loudly,
    /// instead of the whole infra graph quietly producing zero attacker-direction edges.
    /// </summary>
    [Fact]
    public void Reversal_is_not_accidentally_skipped()
    {
        var buildOrderEdge = new TerraformRawEdge(
            FromAddress: "aws_iam_role_policy.order_task_policy", ToAddress: "aws_iam_role.order_task_role");

        var oriented = AttackDirectionOrienter.Reverse([buildOrderEdge]);

        var edge = Assert.Single(oriented);
        Assert.NotEqual(buildOrderEdge.FromAddress, edge.FromAddress);
        Assert.NotEqual(buildOrderEdge.ToAddress, edge.ToAddress);
        Assert.Equal(buildOrderEdge.FromAddress, edge.ToAddress);
        Assert.Equal(buildOrderEdge.ToAddress, edge.FromAddress);
        Assert.True(edge.OrientedAttackDir);
    }

    [Fact]
    public void Empty_input_yields_empty_output()
    {
        Assert.Empty(AttackDirectionOrienter.Reverse([]));
    }
}

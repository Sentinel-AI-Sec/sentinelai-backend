using SentinelAI.Domain.Enums;

namespace SentinelAI.Domain.Tests;

/// <summary>
/// SEC-20 step 4. The tactic ladder constrains which direction a candidate chain may travel, so
/// its ordering is load-bearing in exactly the way <see cref="Confidence"/>'s is: get it wrong
/// and traversal silently finds zero chains, or finds nonsense ones, with nothing erroring.
/// These pin it against a well-meaning reorder.
/// </summary>
public class AttackTacticTests
{
    [Fact]
    public void Tactics_are_ordered_along_the_kill_chain()
    {
        Assert.True(AttackTactic.InitialAccess < AttackTactic.Execution);
        Assert.True(AttackTactic.Execution < AttackTactic.Persistence);
        Assert.True(AttackTactic.Persistence < AttackTactic.PrivilegeEscalation);
        Assert.True(AttackTactic.PrivilegeEscalation < AttackTactic.Collection);
    }

    /// <summary>The ladder the fixture's flagship chain walks, in order.</summary>
    [Fact]
    public void The_flagship_chains_node_types_climb_the_ladder()
    {
        NodeType[] flagship = [NodeType.Pkg, NodeType.Code, NodeType.Task, NodeType.IamRole, NodeType.Resource];

        var tactics = flagship.Select(t => t.Tactic()).ToList();

        Assert.Equal(tactics.OrderBy(t => t), tactics);
        Assert.All(
            tactics.Zip(tactics.Skip(1)),
            pair => Assert.True(pair.First.Precedes(pair.Second)));
    }

    /// <summary>
    /// The rule that discards the <c>iam_role → task</c> edges the infra spine produces by
    /// reversing every Terraform dependency. A real edge, pointing the wrong way for an attacker.
    /// </summary>
    [Fact]
    public void A_role_does_not_lead_back_into_a_workload()
    {
        Assert.False(NodeType.IamRole.Tactic().Precedes(NodeType.Task.Tactic()));
        Assert.True(NodeType.Task.Tactic().Precedes(NodeType.IamRole.Tactic()));
    }

    /// <summary>
    /// Same-tactic movement stays legal: code reaching other code is still Execution, and
    /// rejecting it would break same-layer spread.
    /// </summary>
    [Fact]
    public void A_step_within_one_tactic_is_allowed()
    {
        Assert.True(NodeType.Code.Tactic().Precedes(NodeType.Code.Tactic()));
        Assert.True(NodeType.Code.Tactic().Precedes(NodeType.Image.Tactic()));
    }

    [Fact]
    public void Every_node_type_has_a_tactic()
    {
        foreach (var nodeType in Enum.GetValues<NodeType>())
            Assert.True(Enum.IsDefined(nodeType.Tactic()));
    }
}

using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Tests.Debate;

/// <summary>
/// SEC-31 step 2: <em>"Route each debate turn: reasoning-heavy turns (chaining, validation,
/// adjudication) → high; routine turns (formatting, summarizing) → cheap."</em>
/// </summary>
/// <remarks>
/// The policy is one dictionary, which makes it easy to change by accident — moving the
/// Reporter to the cheap tier to save money would quietly degrade adjudication, and moving the
/// Orchestrator to the high tier would spend reasoning-model money on a four-line briefing.
/// These pin the shipped map so either change has to be deliberate.
/// </remarks>
public class TierRoutingTests
{
    /// <summary>The three turns AID-01 §2.1 calls reasoning-heavy.</summary>
    public static TheoryData<AgentRole> ReasoningRoles() =>
        [AgentRole.Red, AgentRole.Blue, AgentRole.Reporter];

    [Theory]
    [MemberData(nameof(ReasoningRoles))]
    public void Reasoning_turns_go_to_the_high_tier(AgentRole role)
    {
        Assert.Equal(ModelTier.High, new DebateOptions().TierFor(role));
    }

    [Fact]
    public void The_routine_briefing_turn_goes_to_the_cheap_tier()
    {
        Assert.Equal(ModelTier.Cheap, new DebateOptions().TierFor(AgentRole.Orchestrator));
    }

    /// <summary>Every agent that makes a model call has a tier — nothing falls through.</summary>
    [Fact]
    public void Every_role_is_routed()
    {
        var options = new DebateOptions();

        Assert.All(Enum.GetValues<AgentRole>(), role => Assert.Contains(role, options.Tiers.Keys));
    }

    [Fact]
    public void The_policy_is_overridable_per_role()
    {
        var options = new DebateOptions();
        options.Tiers[AgentRole.Reporter] = ModelTier.Cheap;

        Assert.Equal(ModelTier.Cheap, options.TierFor(AgentRole.Reporter));

        // …and overriding one role leaves the others alone.
        Assert.Equal(ModelTier.High, options.TierFor(AgentRole.Red));
    }

    /// <summary>
    /// A role dropped from the map falls back to the shipped default, not to High. The old
    /// blanket fallback made the Orchestrator's routine turn expensive the moment
    /// configuration replaced the dictionary, and nothing reported it.
    /// </summary>
    [Fact]
    public void A_role_missing_from_the_map_keeps_its_shipped_tier()
    {
        var options = new DebateOptions();
        options.Tiers.Remove(AgentRole.Orchestrator);

        Assert.Equal(ModelTier.Cheap, options.TierFor(AgentRole.Orchestrator));
    }

    /// <summary>Editing an options instance must not rewrite the shipped policy.</summary>
    [Fact]
    public void The_default_policy_is_not_shared_between_instances()
    {
        var edited = new DebateOptions();
        edited.Tiers[AgentRole.Red] = ModelTier.Cheap;

        Assert.Equal(ModelTier.High, new DebateOptions().TierFor(AgentRole.Red));
        Assert.Equal(ModelTier.High, DebateOptions.DefaultTiers[AgentRole.Red]);
    }
}

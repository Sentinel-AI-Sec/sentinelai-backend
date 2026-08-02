using SentinelAI.Application.Debate;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Executors;
using SentinelAI.Infrastructure.Agents.Orchestration;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// The three SEC-02 acceptance criteria, one test each. All offline against the scripted
/// provider — no API key, no network, no token spend.
/// </summary>
public class DebateAcceptanceTests
{
    // AC1: Run starts -> three agents execute in sequence sharing session state.
    [Fact]
    public async Task Agents_run_in_order_sharing_session_state()
    {
        var debate = TestDebate.Create();
        var runner = new DebateRunner(debate.Workflow);

        var result = await runner.RunAsync(ScanBrief.Stub());

        Assert.NotNull(result.Audit);

        // Order is the contract: Red asserts, Blue validates, Reporter adjudicates.
        Assert.Equal(
            [AgentRole.Red, AgentRole.Blue, AgentRole.Reporter],
            result.Audit!.Transcript.Select(t => t.Role));

        // Shared state, not three independent runs: the Reporter's audit carries the
        // turns produced by Red and Blue, which it never received directly.
        Assert.Equal(3, result.Audit.Transcript.Count);
        Assert.Contains("ASSERT", result.Audit.Transcript[0].Content);
        Assert.Contains("VALIDATE", result.Audit.Transcript[1].Content);
        Assert.Contains("ADJUDICATE", result.Audit.Summary);

        Assert.True(result.Audit.Converged);
        Assert.False(result.Audit.TerminatedByTurnCap);
        Assert.Equal(1, debate.RedClient.CallCount);
        Assert.Equal(1, debate.BlueClient.CallCount);
        Assert.Equal(1, debate.ReporterClient.CallCount);
    }

    // AC3: Turn-cap exceeded -> orchestrator terminates cleanly; Reporter still outputs.
    [Fact]
    public async Task Turn_cap_terminates_the_debate_and_the_reporter_still_outputs()
    {
        // Blue never converges, so only the turn-cap can stop this.
        var debate = TestDebate.Create(maxRounds: 2, blue: (_, _) => TestDebate.NeverConverges);
        var runner = new DebateRunner(debate.Workflow);

        var result = await runner.RunAsync(ScanBrief.Stub());

        // Terminated cleanly — no exception, and the Reporter produced an audit anyway.
        Assert.NotNull(result.Audit);
        Assert.True(result.Audit!.TerminatedByTurnCap);
        Assert.False(result.Audit.Converged);

        // Exactly MaxRounds of debate, then adjudication. The loop did not run away.
        Assert.Equal(2, debate.RedClient.CallCount);
        Assert.Equal(2, debate.BlueClient.CallCount);
        Assert.Equal(1, debate.ReporterClient.CallCount);
        Assert.Equal(2, result.Audit.Rounds);
        Assert.Equal(5, result.Audit.Transcript.Count); // Red,Blue,Red,Blue,Reporter
    }

    [Fact]
    public async Task Turn_cap_of_one_still_reaches_the_reporter()
    {
        var debate = TestDebate.Create(maxRounds: 1, blue: (_, _) => TestDebate.NeverConverges);
        var runner = new DebateRunner(debate.Workflow);

        var result = await runner.RunAsync(ScanBrief.Stub());

        Assert.NotNull(result.Audit);
        Assert.True(result.Audit!.TerminatedByTurnCap);
        Assert.Equal(1, debate.RedClient.CallCount);
        Assert.Equal(1, debate.ReporterClient.CallCount);
    }

    [Fact]
    public void Turn_cap_below_one_is_rejected()
    {
        var options = new DebateOptions { MaxRounds = 0 };
        Assert.Throws<ArgumentOutOfRangeException>(
            () => DebateWorkflow.Build(new ChatClientFactoryStub(), options));
    }

    // A chain is only as trustworthy as its weakest join (AID-01 3.3).
    [Fact]
    public async Task Chain_inherits_the_weakest_join_confidence()
    {
        var debate = TestDebate.Create(
            blue: (_, _) => "VALIDATE: the code->infra image-name join is INFERRED. "
                          + BlueTeamExecutor.ConvergenceMarker);

        var result = await new DebateRunner(debate.Workflow).RunAsync(ScanBrief.Stub());

        Assert.NotNull(result.Audit);
        Assert.Equal(Confidence.Inferred, result.Audit!.WeakestJoin);
    }

    // AID-01 3.3: unconfirmable is not refuted. A hop Blue could not check must not break
    // the chain — treating it as a break is what made every live run burn the full turn-cap.
    [Fact]
    public async Task An_unresolved_hop_alone_does_not_break_the_chain()
    {
        var debate = TestDebate.Create(
            blue: (_, _) =>
                """
                hop 1: confirmed against packages.lock.json. CONFIRMED
                hop 2: image-name join not settleable from this evidence. UNRESOLVED
                VERDICT: CHAIN_HOLDS
                """);

        var result = await new DebateRunner(debate.Workflow).RunAsync(ScanBrief.Stub());

        Assert.NotNull(result.Audit);
        Assert.Equal(DebateOutcome.Converged, result.Audit!.Outcome);
        Assert.False(result.Audit.TerminatedByTurnCap);
        Assert.Equal(Confidence.Unresolved, result.Audit.WeakestJoin);

        // One round, not the full cap: Red asserted once and was not asked to re-assert.
        Assert.Equal(1, debate.RedClient.CallCount);
    }

    // The verdict is the closing line, not "does this token appear anywhere". Blue now
    // reasons about REFUTED vs UNRESOLVED out loud, so its prose mentions both outcomes.
    [Fact]
    public async Task The_closing_line_decides_the_verdict_not_the_prose_above_it()
    {
        var debate = TestDebate.Create(
            blue: (_, _) =>
                """
                hop 2: this would be CHAIN_BROKEN only if the role were unscoped. It is not.
                VERDICT: CHAIN_HOLDS
                """);

        var result = await new DebateRunner(debate.Workflow).RunAsync(ScanBrief.Stub());

        Assert.NotNull(result.Audit);
        Assert.Equal(DebateOutcome.Converged, result.Audit!.Outcome);
    }

    [Fact]
    public async Task Unresolved_join_is_surfaced_not_dropped()
    {
        var debate = TestDebate.Create(
            blue: (_, _) => "VALIDATE: hop 3 join UNRESOLVED. " + BlueTeamExecutor.ConvergenceMarker);

        var result = await new DebateRunner(debate.Workflow).RunAsync(ScanBrief.Stub());

        Assert.NotNull(result.Audit);
        Assert.Equal(Confidence.Unresolved, result.Audit!.WeakestJoin);
        // Still reported — never silently killed.
        Assert.NotEmpty(result.Audit.Summary);
        Assert.Contains("draft audit", result.Audit.Disclaimer, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>Never actually called — the turn-cap guard rejects the options first.</summary>
internal sealed class ChatClientFactoryStub : SentinelAI.Infrastructure.Agents.Providers.IChatClientFactory
{
    public Microsoft.Extensions.AI.IChatClient Create(
        AgentRole role, ModelTier tier) =>
        new SentinelAI.Infrastructure.Agents.Providers.ScriptedChatClient(role);
}

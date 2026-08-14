using Microsoft.Extensions.Configuration;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// SEC-31's acceptance criterion: <em>"Given a completed audit, when measured, then cost per
/// audit by model tier is recorded"</em> — and its routing half, <em>"reasoning turns use the
/// high tier; routine turns use the cheap tier"</em>.
/// </summary>
/// <remarks>
/// <para>
/// Built the same way <c>ProviderDebateTests</c> is: nothing here names a provider in code,
/// only as a string in a configuration dictionary, and everything downstream — loader, pricing,
/// factory, workflow, runner — is the path the API takes. The token counts are real ones read
/// off the provider's response rather than numbers this test invented, because
/// <see cref="FakeProviderServer"/> answers with a genuine OpenAI-wire <c>usage</c> block.
/// </para>
/// <para>
/// Routing is asserted twice on purpose, at two different depths: that the tier reached the
/// <em>provider</em> (a different model id in the request body) lives in
/// <c>ProviderDebateTests</c>; that the tier is recorded on the <em>turn</em>, which is what
/// the cost breakdown is folded from, is here. Either one alone can pass while spend is
/// attributed to the wrong tier.
/// </para>
/// </remarks>
public class CostTrackingTests
{
    /// <summary>What <see cref="FakeProviderServer"/> reports for every call it serves.</summary>
    private static readonly TokenUsage PerCall = new(10, 20);

    private sealed record Run(DebateResult Result, FakeProviderServer? Server)
    {
        public DraftAudit Audit => Result.Audit
            ?? throw new InvalidOperationException("The debate produced no audit.");

        public AuditCost Cost => Audit.Cost;
    }

    /// <summary>Configuration to a finished, priced audit — exactly as the API does it.</summary>
    private static async Task<Run> RunAsync(Dictionary<string, string?> settings, bool live = true)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

        var models = ModelOptionsLoader.Load(configuration);
        var pricing = ProviderPricing.Load(configuration, models.Provider);

        var server = live ? new FakeProviderServer() : null;
        var factory = new ChatClientFactory(models, server?.AsTransport());
        var workflow = DebateWorkflow.Build(factory, new DebateOptions(), pricing);

        return new Run(await new DebateRunner(workflow).RunAsync(ScanBrief.Stub()), server);
    }

    private static Dictionary<string, string?> Anthropic() => new()
    {
        ["SentinelAI:Models:Provider"] = "Anthropic",
        ["SentinelAI:Models:ApiKey"] = "test-key-never-leaves-the-process",
    };

    private static Dictionary<string, string?> Nim() => new()
    {
        ["SentinelAI:Models:Provider"] = "Nim",
        ["SentinelAI:Models:ApiKey"] = "test-key-never-leaves-the-process",
    };

    private static Dictionary<string, string?> Scripted() => new()
    {
        ["SentinelAI:Models:Provider"] = "Scripted",
    };

    // ---- the acceptance criterion --------------------------------------------------------

    /// <summary>
    /// A completed audit carries a cost per tier: real tokens from the provider, priced at the
    /// provider's rates, split by the tier that served each turn.
    /// </summary>
    [Fact]
    public async Task A_completed_audit_records_cost_per_tier()
    {
        var run = await RunAsync(Anthropic());

        // Red, Blue and Reporter reason; the Orchestrator briefs. Four calls, two tiers.
        var high = run.Cost.For(ModelTier.High);
        var cheap = run.Cost.For(ModelTier.Cheap);

        Assert.NotNull(high);
        Assert.NotNull(cheap);

        Assert.Equal(3, high!.Calls);
        Assert.Equal(1, cheap!.Calls);
        Assert.Equal(new TokenUsage(PerCall.InputTokens * 3, PerCall.OutputTokens * 3), high.Usage);
        Assert.Equal(PerCall, cheap.Usage);

        // Money, at the list prices ProviderPricing carries for this provider.
        var rates = ProviderPricing.DefaultsFor(ModelProvider.Anthropic);
        Assert.Equal(rates.RateFor(ModelTier.High)!.CostOf(high.Usage), high.Cost);
        Assert.Equal(rates.RateFor(ModelTier.Cheap)!.CostOf(cheap.Usage), cheap.Cost);
        Assert.Equal(high.Cost + cheap.Cost, run.Cost.Total);

        Assert.True(run.Cost.Measured);
        Assert.True(run.Cost.FullyRated);
        Assert.Equal("USD", run.Cost.Currency);
    }

    /// <summary>
    /// The routing decision is recorded where the money is counted. Without this the breakdown
    /// could be perfectly arithmetic and still charge Blue's reasoning to the cheap tier.
    /// </summary>
    [Fact]
    public async Task Every_turn_carries_the_tier_that_served_it()
    {
        var run = await RunAsync(Anthropic());

        // The transcript is the three reasoning turns — chaining, validation, adjudication —
        // and every one of them is stamped High. The routine briefing is the Cheap entry in
        // the breakdown; it is not a debate turn, so it is not in here.
        Assert.Equal(
            [AgentRole.Red, AgentRole.Blue, AgentRole.Reporter],
            run.Audit.Transcript.Select(t => t.Role));
        Assert.All(run.Audit.Transcript, turn => Assert.Equal(ModelTier.High, turn.Tier));

        Assert.All(run.Audit.Transcript, turn => Assert.True(turn.Usage.TotalTokens > 0));
    }

    /// <summary>
    /// Moving a role to the other tier moves its spend with it — the breakdown reflects what
    /// ran, not what the shipped policy says should have.
    /// </summary>
    [Fact]
    public async Task Re_routing_a_role_moves_its_spend_to_the_other_tier()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(Anthropic()).Build();
        var models = ModelOptionsLoader.Load(configuration);
        var pricing = ProviderPricing.Load(configuration, models.Provider);

        var options = new DebateOptions();
        options.Tiers[AgentRole.Reporter] = ModelTier.Cheap;

        var server = new FakeProviderServer();
        var workflow = DebateWorkflow.Build(new ChatClientFactory(models, server.AsTransport()), options, pricing);
        var audit = (await new DebateRunner(workflow).RunAsync(ScanBrief.Stub())).Audit!;

        Assert.Equal(ModelTier.Cheap, audit.Transcript.Single(t => t.Role == AgentRole.Reporter).Tier);

        // Red and Blue on High, Reporter and the briefing on Cheap.
        Assert.Equal(2, audit.Cost.For(ModelTier.High)!.Calls);
        Assert.Equal(2, audit.Cost.For(ModelTier.Cheap)!.Calls);
    }

    /// <summary>
    /// The Orchestrator's briefing is a real, billed model call that is deliberately not a
    /// debate turn. It is the one call an audit built from the transcript alone would miss.
    /// </summary>
    [Fact]
    public async Task The_orchestrators_briefing_is_billed_even_though_it_is_not_a_debate_turn()
    {
        var run = await RunAsync(Anthropic());

        Assert.Equal(3, run.Audit.Transcript.Count);      // Red, Blue, Reporter
        Assert.Equal(4, run.Cost.TotalCalls);             // …plus the briefing
        Assert.Equal(run.Server!.Calls.Count, run.Cost.TotalCalls);
        Assert.Equal(PerCall, run.Cost.UsageFor(ModelTier.Cheap));
    }

    [Fact]
    public async Task Every_call_the_provider_served_is_accounted_for()
    {
        var run = await RunAsync(Anthropic());

        var expected = new TokenUsage(
            PerCall.InputTokens * run.Server!.Calls.Count,
            PerCall.OutputTokens * run.Server.Calls.Count);

        Assert.Equal(expected, run.Cost.TotalUsage);
    }

    // ---- the honesty rules ---------------------------------------------------------------

    /// <summary>
    /// NIM's price depends on how it is hosted, so no list price is shipped for it. The tokens
    /// are still counted; the money is not claimed. A zero here must not read as a free scan.
    /// </summary>
    [Fact]
    public async Task A_provider_with_no_published_rates_reports_tokens_without_money()
    {
        var run = await RunAsync(Nim());

        Assert.True(run.Cost.Measured);
        Assert.False(run.Cost.FullyRated);
        Assert.Equal(0m, run.Cost.Total);
        Assert.True(run.Cost.TotalUsage.TotalTokens > 0);
    }

    /// <summary>…and configuring rates for it turns the same run into a priced one.</summary>
    [Fact]
    public async Task Configured_rates_price_a_provider_that_ships_none()
    {
        var settings = Nim();
        settings["SentinelAI:Models:Pricing:High:InputPerMillionTokens"] = "1.00";
        settings["SentinelAI:Models:Pricing:High:OutputPerMillionTokens"] = "10.00";
        settings["SentinelAI:Models:Pricing:Cheap:InputPerMillionTokens"] = "0.10";
        settings["SentinelAI:Models:Pricing:Cheap:OutputPerMillionTokens"] = "1.00";

        var run = await RunAsync(settings);

        Assert.True(run.Cost.FullyRated);
        Assert.True(run.Cost.Total > 0m);
    }

    /// <summary>Configuration outranks the built-in list price, per tier.</summary>
    [Fact]
    public async Task Configured_rates_override_the_built_in_list_price()
    {
        var settings = Anthropic();
        settings["SentinelAI:Models:Pricing:High:InputPerMillionTokens"] = "1000";
        settings["SentinelAI:Models:Pricing:High:OutputPerMillionTokens"] = "1000";

        var run = await RunAsync(settings);

        var negotiated = new TierRate(1000m, 1000m).CostOf(run.Cost.UsageFor(ModelTier.High));
        Assert.Equal(negotiated, run.Cost.CostFor(ModelTier.High));

        // The tier nobody renegotiated keeps its list price.
        Assert.Equal(
            ProviderPricing.DefaultFor(ModelProvider.Anthropic, ModelTier.Cheap)!
                .CostOf(run.Cost.UsageFor(ModelTier.Cheap)),
            run.Cost.CostFor(ModelTier.Cheap));
    }

    /// <summary>
    /// The offline provider is genuinely free — nothing leaves the process — so it reports zero
    /// money while staying rated. That is a different claim from "nobody set a price", and the
    /// audit has to be able to make both.
    /// </summary>
    [Fact]
    public async Task The_offline_provider_is_measured_free_rather_than_unpriced()
    {
        var run = await RunAsync(Scripted(), live: false);

        Assert.True(run.Cost.Measured);
        Assert.True(run.Cost.FullyRated);
        Assert.Equal(0m, run.Cost.Total);
        Assert.True(run.Cost.TotalUsage.TotalTokens > 0);
    }

    // ---- durability ----------------------------------------------------------------------

    /// <summary>
    /// A debate resumed from a checkpoint must still bill the turns it took before the
    /// interruption. An accumulator held by the run would restart at zero and report a long
    /// debate as a cheap one; folding over the turns — which the checkpoint stores — cannot.
    /// </summary>
    [Fact]
    public async Task Cost_survives_a_resume_from_checkpoint()
    {
        var blueShouldFail = 1;
        var debate = TestDebate.Create(blue: (_, _) =>
            Interlocked.Exchange(ref blueShouldFail, 0) == 1
                ? throw new InvalidOperationException("Blue crashed mid-debate.")
                : TestDebate.Converges);

        var runner = new DebateRunner(debate.Workflow);

        var failed = await runner.RunAsync(ScanBrief.Stub());
        Assert.Null(failed.Audit);

        // Red's turn completed before the crash and is restored from the checkpoint rather
        // than re-run, so its tokens exist only in the checkpoint by this point.
        var redTokens = failed.Turns.Single(t => t.Role == AgentRole.Red).Usage;
        Assert.True(redTokens.TotalTokens > 0);

        var resumed = await runner.ResumeAsync(failed.Checkpoints[^1]);

        Assert.NotNull(resumed.Audit);
        Assert.Equal(3, resumed.Audit!.Cost.TotalCalls);
        Assert.Contains(redTokens.InputTokens, resumed.Audit.Transcript.Select(t => t.Usage.InputTokens));
        Assert.True(resumed.Audit.Cost.UsageFor(ModelTier.High).TotalTokens >= redTokens.TotalTokens);
    }
}

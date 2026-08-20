using System.Diagnostics;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;
using SentinelAI.Infrastructure.Observability;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// Collects every <see cref="Activity"/> a block of code emits on the SentinelAI source.
/// </summary>
/// <remarks>
/// <para>
/// An in-process <see cref="ActivityListener"/> rather than a collector. The listener is what
/// makes <c>StartActivity</c> return a real activity at all — with nothing subscribed it
/// returns null and the instrumentation does nothing, which is the correct production default
/// and useless for a test.
/// </para>
/// <para>
/// <b>Filtering by source is not enough, and assuming it was made a test flaky.</b> xunit runs
/// classes in parallel, and <c>FullFlowRegressionTests</c> drives a real debate through the API
/// — on the same <see cref="ActivitySource"/>. A listener alive at that moment collects that
/// debate's spans too, so <c>Assert.Single(… "debate")</c> passed alone and failed in the full
/// suite. Read spans back through <see cref="ForScan"/>, which keeps only the trace belonging to
/// one scan job; <see cref="Finished"/> is everything this listener happened to see.
/// </para>
/// </remarks>
internal sealed class SpanCollector : IDisposable
{
    private readonly ActivityListener _listener;
    private readonly List<Activity> _finished = [];
    private readonly Lock _gate = new();

    public SpanCollector()
    {
        _listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == DebateTracing.SourceName,

            // AllDataAndRecorded, not PropagationData: anything less and the activity is
            // created but its tags are dropped, so every assertion below would read null and
            // the test would be measuring the sampler rather than the instrumentation.
            Sample = (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,

            ActivityStopped = activity =>
            {
                lock (_gate) _finished.Add(activity);
            },
        };

        ActivitySource.AddActivityListener(_listener);
    }

    /// <summary>Every span this listener saw, from any debate, in completion order.</summary>
    public IReadOnlyList<Activity> Finished
    {
        get { lock (_gate) return [.. _finished]; }
    }

    /// <summary>
    /// The spans of one debate: the root span carrying <paramref name="scanJobId"/>, and
    /// everything sharing its trace.
    /// </summary>
    /// <remarks>
    /// Selected by trace id rather than by re-reading the scan job tag on each span, because
    /// only the root carries it — a turn span belongs to its debate by being in the same trace,
    /// which is exactly the nesting the product relies on and this incidentally re-checks.
    /// Empty when no debate with that id was seen, which reads as a failed assertion rather
    /// than as a silent pass over nothing.
    /// </remarks>
    public IReadOnlyList<Activity> ForScan(string scanJobId)
    {
        var all = Finished;

        var root = all.FirstOrDefault(
            a => a.GetTagItem(DebateTracing.Sentinel.ScanJobId) as string == scanJobId);

        return root is null ? [] : [.. all.Where(a => a.TraceId == root.TraceId)];
    }

    public void Dispose() => _listener.Dispose();
}

/// <summary>
/// SEC-36: each agent turn is traced with its tokens, tier and latency, and the debate can be
/// replayed from the trace.
/// </summary>
/// <remarks>
/// <para>
/// These run a <em>real</em> debate over the Scripted provider — the whole workflow, four
/// agents, the real executors — and read the spans it emitted. That is deliberate: the thing
/// most likely to go wrong with instrumentation is not the span-building code, it is a call
/// path that never reaches it, and only running the real workflow covers that.
/// </para>
/// <para>
/// Offline and free: no network, no credentials, no tokens spent.
/// </para>
/// </remarks>
public class DebateTracingTests
{
    private static DebateEngine Engine(TurnTracing tracing) => new(
        new ChatClientFactory(new ModelProviderOptions { Provider = ModelProvider.Scripted }),
        Options.Create(new DebateOptions { MaxRounds = 2 }),
        pricing: null,
        tracing: tracing);

    private static async Task<IReadOnlyList<Activity>> RunAsync(TurnTracing tracing, string scanJobId)
    {
        using var collector = new SpanCollector();

        await Engine(tracing).RunAsync(new ScanBrief(scanJobId, ScanBrief.Stub().Context));

        return collector.ForScan(scanJobId);
    }

    // ---- the acceptance criterion ----------------------------------------------------------

    /// <summary>
    /// Every agent turn produced a span carrying its role, round, tier, tokens and latency.
    /// </summary>
    /// <remarks>
    /// The Orchestrator is asserted by name because it is the turn most likely to be missing:
    /// it does not go through <c>DebateExecutor.RunTurnAsync</c> like the other three, so it is
    /// the one an instrumentation change would silently drop.
    /// </remarks>
    [Fact]
    public async Task Every_agent_turn_is_traced_with_its_tokens_tier_and_latency()
    {
        var spans = await RunAsync(TurnTracing.MetadataOnly, "sec36-metadata");

        var turns = spans
            .Where(s => s.GetTagItem(DebateTracing.Sentinel.Role) is not null)
            .ToList();

        Assert.NotEmpty(turns);

        var roles = turns
            .Select(s => s.GetTagItem(DebateTracing.Sentinel.Role)!.ToString())
            .Distinct()
            .ToList();

        Assert.Contains(nameof(AgentRole.Orchestrator), roles);
        Assert.Contains(nameof(AgentRole.Red), roles);
        Assert.Contains(nameof(AgentRole.Blue), roles);
        Assert.Contains(nameof(AgentRole.Reporter), roles);

        Assert.All(turns, span =>
        {
            Assert.NotNull(span.GetTagItem(DebateTracing.Sentinel.Round));
            Assert.NotNull(span.GetTagItem(DebateTracing.Sentinel.Tier));

            // Zero is a legitimate value — the Scripted provider reports no usage — but the tag
            // must be present, so "the provider said nothing" stays distinguishable from "the
            // turn was never instrumented".
            Assert.NotNull(span.GetTagItem(DebateTracing.GenAi.InputTokens));
            Assert.NotNull(span.GetTagItem(DebateTracing.GenAi.OutputTokens));

            Assert.True(span.Duration > TimeSpan.Zero, $"{span.DisplayName} recorded no duration");
        });
    }

    /// <summary>The debate's own root span carries the scan job id, and the turns nest inside it.</summary>
    /// <remarks>
    /// Nesting is what makes one trace one debate. Without it a backend shows four unrelated
    /// model calls and a reader cannot tell which scan they belong to.
    /// </remarks>
    [Fact]
    public async Task The_debate_root_span_carries_the_scan_job_and_the_turns_nest_inside_it()
    {
        var spans = await RunAsync(TurnTracing.MetadataOnly, "sec36-root");

        var root = Assert.Single(spans, s => s.OperationName == "debate");
        Assert.Equal("sec36-root", root.GetTagItem(DebateTracing.Sentinel.ScanJobId));

        var turns = spans.Where(s => s.GetTagItem(DebateTracing.Sentinel.Role) is not null).ToList();

        Assert.All(turns, turn => Assert.Equal(root.TraceId, turn.TraceId));
    }

    // ---- replay ----------------------------------------------------------------------------

    /// <summary>
    /// With content capture on, the trace replays into the transcript the debate produced.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is SEC-36's "debate replayable from the trace", checked rather than asserted in
    /// prose. The comparison is against the engine's own output, so a replay that quietly lost
    /// a turn, reordered two, or attributed one to the wrong agent fails here.
    /// </para>
    /// <para>
    /// The Orchestrator's seed is excluded from the comparison because the audit's transcript
    /// excludes it by design — round 0 carries the brief, not an assertion. It is still in the
    /// trace, and the previous test is what holds it there.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_captured_debate_replays_into_the_transcript_it_produced()
    {
        using var collector = new SpanCollector();

        var audit = await Engine(TurnTracing.WithContent)
            .RunAsync(new ScanBrief("sec36-replay", ScanBrief.Stub().Context));

        var replay = DebateTraceReplay.From(collector.ForScan("sec36-replay"));

        Assert.Equal("sec36-replay", replay.ScanJobId);

        var debated = replay.Turns.Where(t => t.Round > 0).ToList();

        Assert.Equal(
            audit.Transcript.Select(t => (t.Role, t.Round)).ToList(),
            debated.Select(t => (t.Role, t.Round)).ToList());

        Assert.Equal(
            audit.Transcript.Select(t => t.Content).ToList(),
            debated.Select(t => t.Completion ?? string.Empty).ToList());

        Assert.All(replay.Turns, turn =>
        {
            Assert.True(turn.ContentCaptured);
            Assert.False(string.IsNullOrWhiteSpace(turn.Prompt), $"{turn.Role} has no prompt");
            Assert.True(turn.Succeeded);
        });
    }

    /// <summary>
    /// The transcript a replay renders names the prompt as well as the answer.
    /// </summary>
    /// <remarks>
    /// A transcript of answers alone reads plausibly and hides the usual cause of a bad turn,
    /// which is that the agent was asked the wrong thing — Blue opening with "the user is asking
    /// me to act as the Red Team agent" was diagnosed exactly this way.
    /// </remarks>
    [Fact]
    public async Task The_replayed_transcript_shows_what_each_agent_was_asked()
    {
        using var collector = new SpanCollector();

        await Engine(TurnTracing.WithContent)
            .RunAsync(new ScanBrief("sec36-transcript", ScanBrief.Stub().Context));

        var transcript = DebateTraceReplay.From(collector.ForScan("sec36-transcript")).ToTranscript();

        Assert.Contains("sec36-transcript", transcript);
        Assert.Contains("PROMPT:", transcript);
        Assert.Contains("ANSWER:", transcript);
        Assert.Contains("Red", transcript);
        Assert.Contains("Blue", transcript);
    }

    // ---- the privacy default ----------------------------------------------------------------

    /// <summary>
    /// Metadata-only is the default, and it puts no customer text on any span.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The load-bearing test of the whole feature. Content capture makes the collector a second
    /// destination for job content, so the default has to be provably silent — not "we do not
    /// set that tag as far as anyone remembers".
    /// </para>
    /// <para>
    /// Asserted on the tags rather than by searching the span for a known string, because the
    /// failure being guarded against is a tag added later that nobody thought of as content.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Metadata_only_tracing_puts_no_prompt_or_answer_on_any_span()
    {
        var spans = await RunAsync(TurnTracing.MetadataOnly, "sec36-quiet");

        Assert.All(spans, span =>
        {
            Assert.Null(span.GetTagItem(DebateTracing.GenAi.Prompt));
            Assert.Null(span.GetTagItem(DebateTracing.GenAi.Completion));
        });

        // And the trace says so, rather than leaving a reader to infer it from an absence.
        var replay = DebateTraceReplay.From(spans);

        Assert.NotEmpty(replay.Turns);
        Assert.All(replay.Turns, turn => Assert.False(turn.ContentCaptured));
        Assert.Contains("content not captured", replay.ToTranscript());
    }

    /// <summary>
    /// An engine constructed without a tracing argument is metadata-only.
    /// </summary>
    /// <remarks>
    /// The demo and several tests construct <see cref="DebateEngine"/> by hand. If the omitted
    /// argument meant "capture everything", every one of those would start recording prompts the
    /// moment a collector appeared — which is exactly the way a default becomes a leak.
    /// </remarks>
    [Fact]
    public async Task An_engine_constructed_without_a_tracing_argument_captures_no_content()
    {
        using var collector = new SpanCollector();

        var engine = new DebateEngine(
            new ChatClientFactory(new ModelProviderOptions { Provider = ModelProvider.Scripted }),
            Options.Create(new DebateOptions { MaxRounds = 1 }));

        await engine.RunAsync(new ScanBrief("sec36-default", ScanBrief.Stub().Context));

        Assert.All(
            collector.ForScan("sec36-default"),
            span => Assert.Null(span.GetTagItem(DebateTracing.GenAi.Prompt)));
    }

    // ---- cost when nothing is listening -------------------------------------------------------

    /// <summary>
    /// The debate runs and produces an audit without this test attaching a collector.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The production default is exactly this state — no exporter configured, so no listener —
    /// and it is worth an assertion rather than an assumption: a debate that only worked with a
    /// collector attached would fail in every deployment that has not configured one.
    /// </para>
    /// <para>
    /// It cannot assert that <em>nothing</em> was emitted, and does not pretend to: xunit runs
    /// classes in parallel, so another class's collector may be alive while this runs. What it
    /// does assert is that no activity is left current afterwards, which is the leak this file's
    /// instrumentation could plausibly introduce — a span started and never stopped would show
    /// up here and nowhere else.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_debate_runs_and_leaves_no_activity_open_when_nothing_is_collected()
    {
        var audit = await Engine(TurnTracing.WithContent)
            .RunAsync(new ScanBrief("sec36-silent", ScanBrief.Stub().Context));

        Assert.NotNull(audit);
        Assert.NotEmpty(audit.Transcript);

        Assert.Null(Activity.Current);
    }
}

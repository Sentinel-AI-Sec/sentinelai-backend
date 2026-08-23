using System.Diagnostics;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Observability;

/// <summary>
/// Whether a turn's span carries the prompt and completion text.
/// </summary>
/// <remarks>
/// <para>
/// A value passed down the workflow rather than a static flag, and that is deliberate. A static
/// would be simpler to write and would make the whole suite share one setting: tests that need
/// content and tests that need it off would race, and xunit runs classes in parallel. Threading
/// it through costs four constructor parameters and buys deterministic tests.
/// </para>
/// <para>
/// <see cref="MetadataOnly"/> is the default everywhere. Content capture is opted into once, at
/// composition, from <c>Observability:Tracing:CaptureContent</c>.
/// </para>
/// </remarks>
/// <param name="CaptureContent">True to put prompts and completions on the span.</param>
public sealed record TurnTracing(bool CaptureContent)
{
    /// <summary>Tokens, cost, tier, latency and outcome — no customer text. The default.</summary>
    public static readonly TurnTracing MetadataOnly = new(false);

    /// <summary>Adds prompt and completion, which is what makes a debate replayable.</summary>
    public static readonly TurnTracing WithContent = new(true);
}

/// <summary>
/// SEC-36: one span per agent turn, carrying the prompt, the response, the tokens, the tier and
/// the latency — enough to replay a debate from the trace.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the span is here and not around the workflow.</b> A model call is made in exactly two
/// places: <c>DebateExecutor.RunTurnAsync</c> for Red, Blue and the Reporter, and
/// <c>OrchestratorExecutor.HandleAsync</c> for the seed. Both call this, so a new agent cannot
/// be added that spends tokens nobody traced — the same argument that put the tier and usage
/// stamping in one place rather than in each <c>Interpret</c> override.
/// </para>
/// <para>
/// <b>What "replayable" means here, precisely.</b> A trace is not a recording: replaying it
/// re-reads what each agent was asked and what it answered, in order, which is what a person
/// debugging a bad audit actually needs. It does not re-execute the models, and it cannot —
/// they are not deterministic. <see cref="DebateTraceReplay"/> is the reader, and there is a
/// test that runs a real debate, collects its spans, replays them and compares the result to
/// the transcript the debate itself produced.
/// </para>
/// <para>
/// <b>Cost when nothing is listening.</b> <see cref="ActivitySource.StartActivity"/> returns
/// null with no listener, so an unconfigured deployment pays a null check per turn. Nothing is
/// serialised, and the prompt is never touched.
/// </para>
/// <para>
/// <b>Attribute naming.</b> The <c>gen_ai.*</c> attributes follow the OpenTelemetry semantic
/// conventions for generative AI, which is what makes Langfuse — and any other OTLP backend —
/// render these as model calls rather than as anonymous spans. The <c>sentinelai.*</c> ones are
/// this product's own vocabulary and have no convention to follow.
/// </para>
/// </remarks>
public static class DebateTracing
{
    /// <summary>
    /// The source name a collector subscribes to. Public because a host has to name it in
    /// <c>AddSource</c>, and a test has to name it in an <c>ActivityListener</c>.
    /// </summary>
    public const string SourceName = "SentinelAI.Debate";

    /// <summary>
    /// Sources the Agent Framework and Microsoft.Extensions.AI emit under, subscribed alongside
    /// ours.
    /// </summary>
    /// <remarks>
    /// The framework emits natively only when a client is wrapped with its OpenTelemetry
    /// decorator, which this project does not do — so these usually produce nothing. They are
    /// subscribed anyway because the cost is zero and the alternative is a deployment that turns
    /// the decorator on later and silently exports nothing.
    /// </remarks>
    public static readonly IReadOnlyList<string> FrameworkSourceNames =
        ["Microsoft.Agents.AI", "Microsoft.Extensions.AI", "Experimental.Microsoft.Extensions.AI"];

    private static readonly ActivitySource Source = new(SourceName);

    // ---- attribute names ------------------------------------------------------------------

    /// <summary>OpenTelemetry semantic conventions for generative AI.</summary>
    public static class GenAi
    {
        public const string Operation = "gen_ai.operation.name";
        public const string System = "gen_ai.system";
        public const string RequestModel = "gen_ai.request.model";
        public const string ResponseModel = "gen_ai.response.model";
        public const string ResponseId = "gen_ai.response.id";
        public const string FinishReason = "gen_ai.response.finish_reasons";
        public const string InputTokens = "gen_ai.usage.input_tokens";
        public const string OutputTokens = "gen_ai.usage.output_tokens";
        public const string Prompt = "gen_ai.prompt";
        public const string Completion = "gen_ai.completion";
    }

    /// <summary>This product's own vocabulary — no convention covers these.</summary>
    public static class Sentinel
    {
        public const string ScanJobId = "sentinelai.scan_job_id";
        public const string Role = "sentinelai.agent.role";
        public const string Round = "sentinelai.debate.round";
        public const string Tier = "sentinelai.model.tier";
        public const string Converged = "sentinelai.debate.converged";
        public const string VerdictReadable = "sentinelai.debate.verdict_readable";
        public const string Turns = "sentinelai.debate.turns";
        public const string ContentCaptured = "sentinelai.trace.content_captured";
    }

    // ---- spans ------------------------------------------------------------------------------

    /// <summary>
    /// Opens the root span for one debate. Every turn span nests inside it.
    /// </summary>
    /// <remarks>
    /// Returns null when nothing is listening, and the caller's <c>using</c> handles that. The
    /// scan job id lives here rather than being repeated on each turn: turn spans inherit the
    /// trace, and a reader that has a turn span has the whole trace by definition.
    /// </remarks>
    public static Activity? StartDebate(string scanJobId)
    {
        var activity = Source.StartActivity("debate", ActivityKind.Internal);

        activity?.SetTag(Sentinel.ScanJobId, scanJobId);
        activity?.SetTag(GenAi.Operation, "chat");

        return activity;
    }

    /// <summary>Records how a debate ended, on its root span.</summary>
    public static void RecordOutcome(Activity? debate, int turns, bool converged)
    {
        if (debate is null) return;

        debate.SetTag(Sentinel.Turns, turns);
        debate.SetTag(Sentinel.Converged, converged);
    }

    /// <summary>
    /// Opens the span for one agent turn and records what the agent was asked.
    /// </summary>
    /// <param name="role">Which agent is speaking.</param>
    /// <param name="tier">The tier serving this turn (SEC-31).</param>
    /// <param name="prompt">The text handed to the model.</param>
    /// <param name="tracing">Whether the text may be recorded. Null means metadata only.</param>
    /// <remarks>
    /// <para>
    /// <b>The round is not set here, and that is the point of the split.</b> A turn's round is
    /// not the incoming turn's round — Red opens a new one, Blue and the Reporter answer within
    /// the one they were handed — so the only authoritative value is on the turn the executor
    /// produces, which does not exist until after the model has answered. Stamping the incoming
    /// round here instead put every Red turn in the trace one round early, and the replay test
    /// is what caught it. <see cref="RecordTurn"/> sets it from the turn itself.
    /// </para>
    /// <para>
    /// Returns null when nothing is listening, and the caller's <c>using</c> handles that: the
    /// prompt is never read, nothing is allocated, and the turn runs untouched.
    /// </para>
    /// </remarks>
    public static Activity? StartTurn(AgentRole role, ModelTier tier, string prompt, TurnTracing? tracing)
    {
        var activity = Source.StartActivity($"debate.turn {role}", ActivityKind.Client);

        if (activity is null) return null;

        var captureContent = tracing?.CaptureContent ?? false;

        activity.SetTag(GenAi.Operation, "chat");
        activity.SetTag(Sentinel.Role, role.ToString());
        activity.SetTag(Sentinel.Tier, tier.ToString());

        // Recorded whether or not content was captured, so a reader can tell a debate that had
        // no prompts from one whose prompts were deliberately withheld.
        activity.SetTag(Sentinel.ContentCaptured, captureContent);

        if (captureContent) activity.SetTag(GenAi.Prompt, prompt);

        return activity;
    }

    /// <summary>Records a failed model call on the span, then leaves the caller to rethrow.</summary>
    /// <remarks>
    /// The exception is not swallowed anywhere in this file. Doing so would make an exporter
    /// outage and a provider outage look the same at the call site, and the debate's own error
    /// handling is written for the second.
    /// </remarks>
    public static void RecordFailure(Activity? activity, Exception failure)
    {
        if (activity is null) return;

        activity.SetStatus(ActivityStatusCode.Error, failure.Message);
        activity.AddException(failure);
    }

    /// <summary>
    /// Records the turn the executor produced: its round, and how it read the debate's state.
    /// </summary>
    /// <remarks>
    /// Takes the finished <see cref="DebateTurn"/> rather than loose values so the trace and the
    /// transcript cannot disagree — they are the same object. The convergence flags are here
    /// because they explain why the debate went round again or stopped, which is the first
    /// question anyone asks of a trace with too many turns in it.
    /// </remarks>
    public static void RecordTurn(Activity? activity, DebateTurn turn)
    {
        if (activity is null) return;

        activity.SetTag(Sentinel.Round, turn.Round);
        activity.SetTag(Sentinel.Converged, turn.Converged);
        activity.SetTag(Sentinel.VerdictReadable, turn.VerdictReadable);
    }

    /// <summary>Puts the response's usage, model and text on the span.</summary>
    public static void RecordResponse(Activity? activity, AgentResponse response, TurnTracing? tracing)
    {
        if (activity is null) return;

        Record(activity, response, tracing?.CaptureContent ?? false);
    }

    private static void Record(Activity activity, AgentResponse response, bool captureContent)
    {
        // Zero when the provider reported no usage, which several do. The audit's own cost
        // figure already distinguishes "unmeasured" from "free" through AuditCost.Measured;
        // the span records the same zero rather than omitting the tag, so a turn that made a
        // call is never mistaken for one that did not.
        if (response.Usage is { } usage)
        {
            activity.SetTag(GenAi.InputTokens, usage.InputTokenCount ?? 0);
            activity.SetTag(GenAi.OutputTokens, usage.OutputTokenCount ?? 0);
        }

        if (response.ResponseId is { Length: > 0 } id) activity.SetTag(GenAi.ResponseId, id);
        if (response.FinishReason is { } finish) activity.SetTag(GenAi.FinishReason, finish.ToString());

        // The model id is on the underlying ChatResponse, not on AgentResponse. Read through the
        // raw representation rather than AsChatResponse(), which allocates a new response object
        // per turn to reach one string — and degrade to no tag rather than to a guess, because
        // "which model answered" is exactly the claim a trace should not invent.
        if (response.RawRepresentation is ChatResponse { ModelId: { Length: > 0 } model })
            activity.SetTag(GenAi.ResponseModel, model);

        if (captureContent) activity.SetTag(GenAi.Completion, response.Text ?? string.Empty);
    }
}

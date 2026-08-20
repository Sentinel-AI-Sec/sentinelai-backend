using System.Diagnostics;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Observability;

/// <summary>
/// One agent turn, as recovered from a trace.
/// </summary>
/// <param name="Role">Which agent spoke.</param>
/// <param name="Round">1-based debate round; 0 is the Orchestrator's seed.</param>
/// <param name="Tier">The tier that served it.</param>
/// <param name="Usage">Tokens the provider billed.</param>
/// <param name="Latency">How long the model call took — the span's own duration.</param>
/// <param name="Model">The model that answered, when the provider reported one.</param>
/// <param name="Prompt">What the agent was asked. Null when content was not captured.</param>
/// <param name="Completion">What it answered. Null when content was not captured.</param>
/// <param name="ContentCaptured">
/// Whether this turn's span was allowed to carry text. Distinguishes "the agent said nothing"
/// from "we chose not to record what it said" — the two look identical in a null
/// <paramref name="Completion"/> alone, and only one of them is a defect.
/// </param>
/// <param name="Failure">The exception message, when the model call failed.</param>
public sealed record ReplayedTurn(
    AgentRole Role,
    int Round,
    ModelTier Tier,
    TokenUsage Usage,
    TimeSpan Latency,
    string? Model,
    string? Prompt,
    string? Completion,
    bool ContentCaptured,
    string? Failure)
{
    public bool Succeeded => Failure is null;
}

/// <summary>
/// One debate, recovered from its trace.
/// </summary>
/// <param name="ScanJobId">From the root span. Empty when the root span was not in the input.</param>
/// <param name="Turns">Every turn, in the order they happened.</param>
public sealed record ReplayedDebate(string ScanJobId, IReadOnlyList<ReplayedTurn> Turns)
{
    /// <summary>Tokens across the whole debate.</summary>
    public TokenUsage TotalUsage =>
        Turns.Aggregate(TokenUsage.None, (running, turn) => running + turn.Usage);

    /// <summary>Wall-clock time spent inside model calls. Not the debate's elapsed time.</summary>
    /// <remarks>
    /// The distinction matters when someone asks why an audit took six minutes: the sum of the
    /// turn latencies is the part a faster model would fix, and the difference between it and
    /// the root span's duration is everything else.
    /// </remarks>
    public TimeSpan ModelTime =>
        Turns.Aggregate(TimeSpan.Zero, (running, turn) => running + turn.Latency);

    /// <summary>The transcript as text, for a human reading a failed audit.</summary>
    /// <remarks>
    /// Prints the prompt as well as the answer. A transcript of answers alone reads plausibly
    /// and hides the usual cause of a bad turn, which is that the agent was asked the wrong
    /// thing — Blue opening with "the user is asking me to act as the Red Team agent" was
    /// diagnosed exactly this way.
    /// </remarks>
    public string ToTranscript()
    {
        var text = new System.Text.StringBuilder();

        text.AppendLine($"debate {ScanJobId} — {Turns.Count} turn(s), {TotalUsage}, {ModelTime.TotalSeconds:0.0}s in model calls");

        foreach (var turn in Turns)
        {
            text.AppendLine();
            text.AppendLine($"── {turn.Role} · round {turn.Round} · {turn.Tier} · {turn.Usage} · {turn.Latency.TotalSeconds:0.00}s"
                + (turn.Model is { } model ? $" · {model}" : string.Empty));

            if (turn.Failure is { } failure)
            {
                text.AppendLine($"   FAILED: {failure}");
                continue;
            }

            if (!turn.ContentCaptured)
            {
                text.AppendLine("   (content not captured — Observability:Tracing:CaptureContent is off)");
                continue;
            }

            text.AppendLine($"   PROMPT: {turn.Prompt}");
            text.AppendLine($"   ANSWER: {turn.Completion}");
        }

        return text.ToString();
    }
}

/// <summary>
/// SEC-36's "debate replayable from the trace", as a reader rather than as a claim.
/// </summary>
/// <remarks>
/// <para>
/// <b>What replay is and is not.</b> It re-reads what each agent was asked and what it answered,
/// in order, with the tokens and latency each turn cost. It does not re-execute anything — the
/// models are not deterministic and a trace is not a recording. What a person debugging a bad
/// audit actually needs is the first thing, and the trace has it.
/// </para>
/// <para>
/// <b>Why a reader exists at all, when Langfuse already renders spans.</b> Because a claim that
/// a debate is replayable is only worth as much as the thing that checks it. With this type
/// there is a test that runs a real debate, collects its spans in-process, replays them, and
/// compares the result to the transcript the debate itself produced. Without it, "replayable"
/// is a sentence in a ticket — which is the category of unverified claim this project has
/// already been caught by more than once.
/// </para>
/// <para>
/// It reads <see cref="Activity"/> objects, so the same code serves the in-process test and any
/// tooling that pulls spans back out of a backend, without either needing an OTLP client.
/// </para>
/// </remarks>
public static class DebateTraceReplay
{
    /// <summary>
    /// Rebuilds a debate from its spans. Spans that are not this debate's are ignored.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Ordered by when each span started, not by round.</b> Round is not a total order — Red
    /// and Blue share a round number, and the Reporter closes the last one — so sorting by it
    /// would put a round's turns in an arbitrary order and the transcript would read wrong in
    /// exactly the place a reader is looking. Start time is the order they happened, which is
    /// what a transcript means.
    /// </para>
    /// <para>
    /// The root span contributes the scan job id and nothing else; turn spans carry everything
    /// about a turn. A collection with no root replays fine and reports an empty id rather than
    /// failing — a partial trace is still worth reading.
    /// </para>
    /// </remarks>
    public static ReplayedDebate From(IEnumerable<Activity> activities)
    {
        ArgumentNullException.ThrowIfNull(activities);

        var all = activities.ToList();

        var scanJobId = all
            .Select(a => Tag(a, DebateTracing.Sentinel.ScanJobId))
            .FirstOrDefault(id => !string.IsNullOrEmpty(id))
            ?? string.Empty;

        var turns = all
            .Where(a => Tag(a, DebateTracing.Sentinel.Role) is { Length: > 0 })
            .OrderBy(a => a.StartTimeUtc)
            .Select(ToTurn)
            .ToList();

        return new ReplayedDebate(scanJobId, turns);
    }

    private static ReplayedTurn ToTurn(Activity activity) => new(
        Role: Enum.TryParse<AgentRole>(Tag(activity, DebateTracing.Sentinel.Role), out var role)
            ? role
            // Not a throw: a span from a newer build naming a role this one has never heard of
            // should still appear in the transcript rather than abort the replay of the eleven
            // turns around it.
            : AgentRole.Orchestrator,
        Round: Int(activity, DebateTracing.Sentinel.Round),
        Tier: Enum.TryParse<ModelTier>(Tag(activity, DebateTracing.Sentinel.Tier), out var tier)
            ? tier
            : ModelTier.High,
        Usage: new TokenUsage(
            Int(activity, DebateTracing.GenAi.InputTokens),
            Int(activity, DebateTracing.GenAi.OutputTokens)),
        Latency: activity.Duration,
        Model: Tag(activity, DebateTracing.GenAi.ResponseModel),
        Prompt: Tag(activity, DebateTracing.GenAi.Prompt),
        Completion: Tag(activity, DebateTracing.GenAi.Completion),
        ContentCaptured: Tag(activity, DebateTracing.Sentinel.ContentCaptured) == bool.TrueString,
        Failure: activity.Status == ActivityStatusCode.Error
            ? activity.StatusDescription ?? "the model call failed with no message"
            : null);

    /// <summary>
    /// A tag's value as a string, or null.
    /// </summary>
    /// <remarks>
    /// <c>GetTagItem</c> rather than <c>Tags</c>: the latter enumerates and boxes on every
    /// lookup, and this does eight lookups per turn.
    /// </remarks>
    private static string? Tag(Activity activity, string name) =>
        activity.GetTagItem(name)?.ToString();

    private static int Int(Activity activity, string name) =>
        activity.GetTagItem(name) switch
        {
            int value => value,
            long value => (int)value,
            // Tags survive a round trip through an exporter as strings, so a replay reading
            // spans back out of a backend rather than out of memory sees text here.
            string text when int.TryParse(text, out var parsed) => parsed,
            _ => 0,
        };
}

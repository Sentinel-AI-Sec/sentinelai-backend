namespace SentinelAI.Infrastructure.Orchestration;

/// <summary>
/// How the scan-time worker polls and how much work it runs at once (SEC-46).
/// </summary>
/// <remarks>
/// Bound from the <c>Scanning:Worker</c> configuration section. Every value here is a deployment
/// decision rather than something the process can derive: how fast a queued scan should start,
/// and how many concurrent debates this deployment's model quota and budget can absorb.
/// </remarks>
public sealed class ScanWorkerOptions
{
    public const string SectionName = "Scanning:Worker";

    /// <summary>
    /// Whether this process runs scans at all.
    /// </summary>
    /// <remarks>
    /// On by default, because a deployment that accepts scans and never runs them is the bug this
    /// ticket exists to fix. It is configurable so that an API instance can be scaled separately
    /// from the workers, and so the test host can keep a background thread out of tests that seed
    /// queued jobs of their own.
    /// </remarks>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// How long to wait after finding an empty queue before asking again.
    /// </summary>
    /// <remarks>
    /// Only paid when the queue is empty — a claim that succeeds loops straight back for the next
    /// job, so a backlog drains at the speed of the pipeline rather than at this interval. Five
    /// seconds is a compromise between the latency a developer notices when pushing a commit and
    /// the cost of a query against an idle table.
    /// </remarks>
    public int PollIntervalSeconds { get; set; } = 5;

    /// <summary>The poll interval as a <see cref="TimeSpan"/>, floored at one second.</summary>
    /// <remarks>
    /// Floored rather than validated: a mistyped zero would otherwise spin the loop against the
    /// database as fast as the thread allows, which looks like a hung process rather than like a
    /// bad setting.
    /// </remarks>
    public TimeSpan PollInterval => TimeSpan.FromSeconds(Math.Max(1, PollIntervalSeconds));
}

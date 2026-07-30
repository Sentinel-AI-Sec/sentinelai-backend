using System.ClientModel.Primitives;

namespace SentinelAI.Infrastructure.Agents.Providers;

/// <summary>
/// Retries transient server failures but never a timeout.
/// </summary>
/// <remarks>
/// <para>The two failure classes need opposite treatment, and the default policy conflates them:</para>
/// <list type="bullet">
/// <item>
/// A <b>timeout</b> means the request already consumed its full budget. Retrying does not
/// recover it, it multiplies it — a 120s ceiling retried three times became a measured
/// 480s wait with no output, which is what made the debate look hung.
/// </item>
/// <item>
/// A <b>503 / 429</b> is transient capacity on a shared endpoint. Measured on this model:
/// three identical probes gave FAIL, OK, FAIL within seconds. These fail fast and usually
/// succeed on the next attempt, so refusing to retry them throws away a run for nothing —
/// which is exactly how a completed debate lost its Reporter turn and produced no audit.
/// </item>
/// </list>
/// </remarks>
internal sealed class DebateRetryPolicy(int maxRetries) : ClientRetryPolicy(maxRetries)
{
    protected override bool ShouldRetry(PipelineMessage message, Exception? exception) =>
        !IsTimeout(exception) && base.ShouldRetry(message, exception);

    protected override ValueTask<bool> ShouldRetryAsync(PipelineMessage message, Exception? exception) =>
        IsTimeout(exception)
            ? ValueTask.FromResult(false)
            : base.ShouldRetryAsync(message, exception);

    /// <summary>
    /// The client surfaces its network timeout as a cancellation, so that — not
    /// <see cref="TimeoutException"/> alone — is the signal to stop.
    /// </summary>
    private static bool IsTimeout(Exception? exception) =>
        exception is OperationCanceledException or TimeoutException;
}

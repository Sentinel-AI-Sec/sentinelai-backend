namespace SentinelAI.Domain.Abstractions.Repositories;

/// <summary>
/// The result of asking to spend one unit of a tenant's daily scan quota.
/// </summary>
/// <param name="Allowed">Whether the unit was consumed. False means the limit was already reached.</param>
/// <param name="Used">Scans submitted today, after this call.</param>
/// <param name="Limit">The plan's daily allowance, echoed back so a refusal can explain itself.</param>
public readonly record struct QuotaDecision(bool Allowed, int Used, int Limit)
{
    /// <summary>How long until the counter resets, from <paramref name="nowUtc"/>.</summary>
    /// <remarks>
    /// Midnight UTC, because the counter is keyed on the UTC day. Rounded up to at least one
    /// second: a <c>Retry-After: 0</c> invites an immediate retry that is certain to fail again.
    /// </remarks>
    public static int RetryAfterSeconds(DateTime nowUtc)
    {
        var midnight = nowUtc.Date.AddDays(1);
        var seconds = (int)Math.Ceiling((midnight - nowUtc).TotalSeconds);

        return Math.Max(seconds, 1);
    }
}

/// <summary>
/// Spends a tenant's daily scan quota, atomically.
/// </summary>
/// <remarks>
/// <para>
/// <b>Consuming and checking are the same operation, deliberately.</b> A separate "is there room?"
/// followed by "take one" is a race with a window between them, and the window is exactly wide
/// enough for a CI matrix firing ten parallel jobs to all read the same count and all be allowed.
/// This returns whether it took the unit, so a refusal never charges one and an allowance is never
/// granted twice.
/// </para>
/// <para>
/// <b>Failed scans are not refunded; refused submissions are.</b> The two are different events and
/// the distinction is the whole of <see cref="ReleaseAsync"/>. A scan accepted with a 202 that
/// later fails in the pipeline has consumed an upload, a normalization pass and a pipeline slot —
/// refunding it would also make a crash-looping bundle free to retry forever. A submission the API
/// refused at the door was never a scan at all: a CI job with a malformed metadata file would
/// otherwise spend a customer's entire daily allowance on requests that did nothing, and leave them
/// rate limited with no scans to show for it.
/// </para>
/// </remarks>
public interface IScanQuotaCounter
{
    /// <summary>
    /// Consumes one unit for <paramref name="utcDay"/> if the tenant is under
    /// <paramref name="limit"/>.
    /// </summary>
    Task<QuotaDecision> TryConsumeAsync(
        Guid tenantId, int limit, DateOnly utcDay, CancellationToken ct = default);

    /// <summary>
    /// Gives back a unit taken by <see cref="TryConsumeAsync"/> for a request that was then
    /// refused.
    /// </summary>
    /// <remarks>
    /// The unit is taken up front and handed back on refusal, rather than checked up front and
    /// taken on success. Checking first leaves a window between the check and the take, and that
    /// window is exactly wide enough for a CI matrix firing ten parallel jobs to all read the same
    /// count and all be allowed — which is a paywall bypass, not a rounding error. Holding the unit
    /// for the duration of the request has no such window.
    /// </remarks>
    Task ReleaseAsync(Guid tenantId, DateOnly utcDay, CancellationToken ct = default);

    /// <summary>
    /// Reads the count without spending anything — for the billing screen's usage line.
    /// </summary>
    Task<int> UsedTodayAsync(Guid tenantId, DateOnly utcDay, CancellationToken ct = default);
}

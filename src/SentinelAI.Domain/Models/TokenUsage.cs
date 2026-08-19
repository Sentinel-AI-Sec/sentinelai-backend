using System.Text.Json.Serialization;

namespace SentinelAI.Domain.Models;

/// <summary>
/// Tokens billed for one model call, or for any group of them. The unit providers price in
/// (SEC-31): cost is tokens × the rate for the tier that served them.
/// </summary>
/// <remarks>
/// <para>
/// Input and output are kept apart rather than summed, because every provider charges them at
/// different rates — output is typically four to five times input. A single total cannot be
/// priced, and a total that <em>looks</em> priceable is worse than one that obviously is not.
/// </para>
/// <para>
/// This travels on <see cref="DebateTurn"/>, which means it is serialized into every
/// checkpoint. That is deliberate: a debate resumed from a checkpoint must still report what
/// the turns before the interruption cost, and an accumulator held in memory by the run could
/// not survive the process that owned it.
/// </para>
/// </remarks>
/// <param name="InputTokens">Prompt tokens the provider billed for.</param>
/// <param name="OutputTokens">Completion tokens the provider billed for.</param>
public readonly record struct TokenUsage(long InputTokens, long OutputTokens)
{
    /// <summary>No call was made, or the provider reported nothing.</summary>
    public static readonly TokenUsage None = new(0, 0);

    [JsonIgnore]
    public long TotalTokens => InputTokens + OutputTokens;

    /// <summary>True when the provider reported no usage at all for this call.</summary>
    [JsonIgnore]
    public bool IsEmpty => InputTokens == 0 && OutputTokens == 0;

    public static TokenUsage operator +(TokenUsage left, TokenUsage right) =>
        new(left.InputTokens + right.InputTokens, left.OutputTokens + right.OutputTokens);

    /// <summary>Named alternative to <c>operator +</c>, for callers that cannot use it.</summary>
    public TokenUsage Add(TokenUsage other) => this + other;

    public override string ToString() => $"{InputTokens} in / {OutputTokens} out";
}

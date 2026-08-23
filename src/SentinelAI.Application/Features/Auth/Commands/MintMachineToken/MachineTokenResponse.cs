namespace SentinelAI.Application.Features.Auth.Commands.MintMachineToken;

/// <summary>
/// A freshly minted machine token. <b>The only time the token is ever readable</b> — nothing is
/// persisted, so it cannot be fetched again and a caller who loses it mints another.
/// </summary>
public sealed record MachineTokenResponse
{
    /// <summary>The JWT itself. Goes into the <c>SENTINELAI_MACHINE_TOKEN</c> repository secret.</summary>
    public required string Token { get; init; }

    public required DateTime ExpiresAt { get; init; }

    /// <summary>
    /// The scopes baked into <see cref="Token"/>, echoed so a caller can see what it can do
    /// without decoding it. A readback, not a second source of truth.
    /// </summary>
    public required IReadOnlyList<string> Scopes { get; init; }

    /// <summary>The tenant the token acts for — the caller's own, never one they asked for.</summary>
    public required Guid TenantId { get; init; }
}

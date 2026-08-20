namespace SentinelAI.Api.Configuration;

/// <summary>
/// SEC-35's "secrets in Azure Key Vault" (audit 35-A): which vault, and how its secret names
/// map onto configuration keys.
/// </summary>
/// <remarks>
/// <para>
/// <b>Unconfigured is the default and adds no configuration source at all.</b> No vault client
/// is constructed, no credential is resolved, and nothing reaches the network. That is not
/// laxness: every test, the offline demo and a fresh clone run in exactly this state, and a
/// deployment that could not start without a vault would be one nobody could develop against.
/// </para>
/// <para>
/// <b>Why the alias map exists.</b> The standard convention encodes hierarchy as a double
/// hyphen, so <c>Authentication--Jwt--SigningKey</c> becomes <c>Authentication:Jwt:SigningKey</c>
/// and no mapping is needed. This deployment's vault predates that: its secrets are named
/// <c>sql-default-connection</c>, <c>nim-red-key</c> and so on. Renaming live secrets to suit a
/// convention is a change with an outage in it; declaring the mapping is not. Both are
/// supported, and the convention is what applies when no alias is declared.
/// </para>
/// </remarks>
public sealed class KeyVaultOptions
{
    public const string SectionName = "KeyVault";

    /// <summary>
    /// The vault, e.g. <c>https://sentinelai-kv.vault.azure.net/</c>. Empty disables the whole
    /// feature.
    /// </summary>
    public string? Uri { get; set; }

    /// <summary>
    /// Vault secret name to configuration key, for secrets not named by the <c>--</c>
    /// convention.
    /// </summary>
    /// <remarks>
    /// Written the way it reads in the vault, e.g.
    /// <c>"sql-default-connection": "ConnectionStrings:DefaultConnection"</c>. A secret with no
    /// entry falls through to the convention rather than being skipped — a vault holding both
    /// naming styles is the normal case during a migration, not an error.
    /// </remarks>
    public IDictionary<string, string> SecretNames { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// How often to re-read the vault, in minutes. Zero or absent reads once, at startup.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off by default, deliberately. Reloading is what makes a rotated secret take effect
    /// without a restart, and it is also a poll against a metered service on every instance —
    /// so it is a decision a deployment makes rather than one it inherits.
    /// </para>
    /// <para>
    /// Note what reloading does <em>not</em> do here: the model options, the egress catalog and
    /// the tracing options are all read once at registration, so a rotated model key reaches
    /// them on the next restart regardless. What reloading covers is everything read through
    /// <c>IConfiguration</c> at request time — the JWT signing key among them.
    /// </para>
    /// </remarks>
    public int ReloadIntervalMinutes { get; set; }

    /// <summary>True when a vault has been named.</summary>
    public bool IsEnabled => !string.IsNullOrWhiteSpace(Uri);

    /// <summary>The reload interval as a timespan, or null for read-once.</summary>
    public TimeSpan? ReloadInterval =>
        ReloadIntervalMinutes > 0 ? TimeSpan.FromMinutes(ReloadIntervalMinutes) : null;
}

/// <summary>
/// What the Key Vault configuration source did at startup, so it can be logged once the host
/// has a logger.
/// </summary>
/// <remarks>
/// Configuration sources are added before the container exists, so nothing at that point can
/// log. Recording the outcome and logging it from <c>UseApiServices</c> is what stops "secrets
/// come from the vault" being a belief rather than an observation — the single most common way
/// a Key Vault integration is wrong is that it is silently not running.
/// </remarks>
/// <param name="Enabled">False when no vault was configured.</param>
/// <param name="VaultUri">The vault that was read, or null.</param>
/// <param name="SecretCount">How many secrets the source loaded. Zero with a vault configured is worth noticing.</param>
/// <param name="AliasCount">How many secrets were mapped by an explicit alias rather than by convention.</param>
/// <param name="ReloadInterval">Null when the vault is read once at startup.</param>
public sealed record KeyVaultLoadResult(
    bool Enabled,
    string? VaultUri,
    int SecretCount,
    int AliasCount,
    TimeSpan? ReloadInterval)
{
    public static readonly KeyVaultLoadResult NotConfigured = new(false, null, 0, 0, null);
}

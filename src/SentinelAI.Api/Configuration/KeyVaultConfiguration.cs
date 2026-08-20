using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace SentinelAI.Api.Configuration;

/// <summary>
/// Maps this deployment's vault secret names onto configuration keys.
/// </summary>
/// <remarks>
/// <para>
/// Two rules, in order. An explicit alias from <see cref="KeyVaultOptions.SecretNames"/> wins;
/// otherwise the standard convention applies, where a double hyphen is the section separator
/// (<c>Authentication--Jwt--SigningKey</c> → <c>Authentication:Jwt:SigningKey</c>).
/// </para>
/// <para>
/// <b>The failure mode this class exists to prevent is silence.</b> A secret loaded under a key
/// nothing reads does not throw, does not warn, and leaves the application running on whatever
/// the committed <c>appsettings.json</c> said — which for the JWT signing key is an empty string
/// and for the provider key is nothing at all. The mapping is therefore explicit and unit
/// tested, rather than being a convention everyone assumes holds.
/// </para>
/// </remarks>
internal sealed class SentinelSecretManager(IReadOnlyDictionary<string, string> aliases) : KeyVaultSecretManager
{
    /// <summary>How many secrets were resolved through an alias rather than by convention.</summary>
    /// <remarks>
    /// Counted so the boot log can say so. "The vault is wired up" and "the vault is wired up
    /// and the six secrets you renamed are being found" are different claims, and only the
    /// second is worth reading.
    /// </remarks>
    public int AliasHits { get; private set; }

    /// <summary>How many secrets the source loaded in total.</summary>
    public int Loaded { get; private set; }

    public override string GetKey(KeyVaultSecret secret)
    {
        Loaded++;

        if (aliases.TryGetValue(secret.Name, out var alias))
        {
            AliasHits++;
            return alias;
        }

        return base.GetKey(secret);
    }
}

/// <summary>
/// Adds Azure Key Vault as a configuration source when — and only when — one is configured
/// (SEC-35, audit 35-A).
/// </summary>
public static class KeyVaultConfiguration
{
    /// <summary>
    /// Reads <c>KeyVault</c> from the configuration built so far and, if a vault is named,
    /// layers it on top.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Layered last, so the vault wins.</b> Configuration sources are last-writer-wins, and a
    /// vault that lost to a committed <c>appsettings.json</c> would be a vault that changes
    /// nothing — the most expensive kind of no-op, because it looks like it is working.
    /// Environment variables are the one thing that can still override it, which is what makes a
    /// local run and a container debug session possible without touching the vault.
    /// </para>
    /// <para>
    /// <b><see cref="DefaultAzureCredential"/>, not a client secret.</b> On the Container App
    /// this resolves to the managed identity, so there is no credential to store, rotate or
    /// leak — which is the point of moving secrets into a vault in the first place. Locally it
    /// falls back to the developer's <c>az login</c>, so the same code path works on a laptop
    /// without a second configuration branch to get wrong.
    /// </para>
    /// <para>
    /// <b>A configured vault that cannot be read is a boot failure, not a warning.</b> Starting
    /// anyway means running on the committed defaults: an empty JWT signing key, no provider
    /// credential, and a connection string pointing nowhere. Those surface later, one at a time,
    /// far from the cause — the exact shape of failure <c>ProviderReadiness</c> was written to
    /// stop. The exception is rethrown with the vault named, because the underlying message
    /// (<c>ManagedIdentityCredential authentication unavailable</c>) does not say which vault or
    /// which setting asked for it.
    /// </para>
    /// </remarks>
    public static KeyVaultLoadResult AddSentinelKeyVault(this IConfigurationManager configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var options = new KeyVaultOptions();

        // Bind, not Get<T>: SecretNames is a getter-only dictionary, which Get<T> leaves empty
        // while reporting success — the silent-empty-binding failure this codebase has been
        // caught by before.
        configuration.GetSection(KeyVaultOptions.SectionName).Bind(options);

        if (!options.IsEnabled) return KeyVaultLoadResult.NotConfigured;

        if (!Uri.TryCreate(options.Uri!.Trim(), UriKind.Absolute, out var vaultUri))
        {
            throw new InvalidOperationException(
                $"'{KeyVaultOptions.SectionName}:Uri' is '{options.Uri}', which is not an absolute "
                + "URI. Expected something like https://sentinelai-kv.vault.azure.net/.");
        }

        var manager = new SentinelSecretManager(options.SecretNames.AsReadOnly());

        try
        {
            configuration.AddAzureKeyVault(
                vaultUri,
                new DefaultAzureCredential(),
                new AzureKeyVaultConfigurationOptions
                {
                    Manager = manager,
                    ReloadInterval = options.ReloadInterval,
                });
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Could not read secrets from the key vault '{vaultUri}' named by "
                + $"'{KeyVaultOptions.SectionName}:Uri'. The application will not start on its "
                + "committed defaults, because those carry no signing key and no provider "
                + $"credential. Underlying error: {ex.Message}", ex);
        }

        return new KeyVaultLoadResult(
            Enabled: true,
            VaultUri: vaultUri.ToString(),
            SecretCount: manager.Loaded,
            AliasCount: manager.AliasHits,
            ReloadInterval: options.ReloadInterval);
    }
}

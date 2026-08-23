using System.Reflection;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using SentinelAI.Api.Configuration;

namespace SentinelAI.Integration.Tests.Retention;

/// <summary>
/// SEC-35's "secrets in Azure Key Vault" (audit 35-A), at the level that can be tested without
/// a vault: whether the source is added at all, and what each secret name maps onto.
/// </summary>
/// <remarks>
/// <para>
/// <b>What is not covered, stated rather than implied.</b> Nothing here contacts Azure,
/// resolves a credential, or proves that a managed identity has the right role assignment. Those
/// need a vault and an identity, and a test that mocked them would be asserting against its own
/// mock. What <em>is</em> covered is the pair of failures that actually happen: the source
/// silently not being added, and a secret being loaded under a key nothing reads.
/// </para>
/// <para>
/// Both are silent by nature. Neither throws, and the symptom of either is an empty signing key
/// or an absent provider credential surfacing three layers away — which is why the boot log says
/// which case a running instance is in.
/// </para>
/// </remarks>
public class KeyVaultConfigurationTests
{
    private static ConfigurationManager Config(params (string Key, string? Value)[] settings)
    {
        var configuration = new ConfigurationManager();
        configuration.AddInMemoryCollection(settings.ToDictionary(s => s.Key, s => s.Value));
        return configuration;
    }

    // ---- when the source is added -----------------------------------------------------------

    /// <summary>
    /// No vault configured adds no source and touches no network.
    /// </summary>
    /// <remarks>
    /// The state every test, the offline demo and a fresh clone run in. A version of this that
    /// tried to resolve a credential would fail on any machine without <c>az login</c>, which is
    /// most CI runners.
    /// </remarks>
    [Fact]
    public void An_unconfigured_vault_adds_no_configuration_source()
    {
        var configuration = Config();
        var before = configuration.Sources.Count;

        var result = configuration.AddSentinelKeyVault();

        Assert.False(result.Enabled);
        Assert.Null(result.VaultUri);
        Assert.Equal(before, configuration.Sources.Count);
    }

    /// <summary>Whitespace is not a vault.</summary>
    /// <remarks>
    /// An environment variable set to an empty string is how a deployment "unsets" a value in
    /// Container Apps, and it arrives here as <c>""</c> rather than as absent.
    /// </remarks>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void A_blank_vault_uri_is_treated_as_unconfigured(string uri)
    {
        Assert.False(Config(($"{KeyVaultOptions.SectionName}:Uri", uri)).AddSentinelKeyVault().Enabled);
    }

    /// <summary>
    /// A malformed vault URI fails at startup, naming the setting.
    /// </summary>
    /// <remarks>
    /// Rather than being skipped. A typo that produced "no vault configured" would start the
    /// application on its committed defaults — an empty signing key, no provider credential —
    /// and the operator's next signal would be a 401 or a boot-time provider check failing for
    /// what looks like an unrelated reason.
    /// </remarks>
    [Fact]
    public void A_malformed_vault_uri_is_refused_at_startup_rather_than_skipped()
    {
        var failure = Assert.Throws<InvalidOperationException>(
            () => Config(($"{KeyVaultOptions.SectionName}:Uri", "sentinelai-kv")).AddSentinelKeyVault());

        Assert.Contains("not an absolute URI", failure.Message);
        Assert.Contains($"{KeyVaultOptions.SectionName}:Uri", failure.Message);
    }

    // ---- what each secret name maps onto ------------------------------------------------------

    /// <summary>
    /// The standard convention applies to any secret without an explicit alias.
    /// </summary>
    /// <remarks>
    /// A double hyphen is the section separator, so a vault named to the convention needs no
    /// configuration at all.
    /// </remarks>
    [Theory]
    [InlineData("Authentication--Jwt--SigningKey", "Authentication:Jwt:SigningKey")]
    [InlineData("Cors--AllowedOrigins--0", "Cors:AllowedOrigins:0")]
    [InlineData("CorpusVersion", "CorpusVersion")]
    public void A_secret_with_no_alias_follows_the_double_hyphen_convention(string secret, string expected)
    {
        Assert.Equal(expected, Manager().GetKey(new KeyVaultSecret(secret, "value")));
    }

    /// <summary>
    /// An explicit alias wins, which is what lets the deployment's existing names keep working.
    /// </summary>
    /// <remarks>
    /// These are the names in the live vault (see the credential inventory):
    /// <c>sql-default-connection</c>, <c>nim-red-key</c>. Under the convention alone they would
    /// load as configuration keys called <c>sql-default-connection</c> and <c>nim-red-key</c> —
    /// keys nothing in this application reads, so the secrets would be present and inert.
    /// </remarks>
    [Theory]
    [InlineData("sql-default-connection", "ConnectionStrings:DefaultConnection")]
    [InlineData("nim-red-key", "SentinelAI:Models:Agents:Red:ApiKey")]
    [InlineData("jwt-signing-key", "Authentication:Jwt:SigningKey")]
    public void An_explicitly_mapped_secret_lands_on_the_key_the_application_reads(
        string secret, string expected)
    {
        Assert.Equal(expected, Manager().GetKey(new KeyVaultSecret(secret, "value")));
    }

    /// <summary>Alias lookup ignores case, because vault names are not case-sensitive.</summary>
    [Fact]
    public void Alias_lookup_is_case_insensitive()
    {
        Assert.Equal(
            "ConnectionStrings:DefaultConnection",
            Manager().GetKey(new KeyVaultSecret("SQL-Default-Connection", "value")));
    }

    /// <summary>
    /// The manager counts what it resolved, so the boot log can report it.
    /// </summary>
    /// <remarks>
    /// "The vault is wired up" and "the vault is wired up and the secrets you renamed are being
    /// found" are different claims, and only the second is worth reading in a log.
    /// </remarks>
    [Fact]
    public void The_manager_counts_secrets_and_alias_hits_for_the_boot_log()
    {
        var manager = Manager();

        manager.GetKey(new KeyVaultSecret("sql-default-connection", "v"));
        manager.GetKey(new KeyVaultSecret("Authentication--Jwt--SigningKey", "v"));
        manager.GetKey(new KeyVaultSecret("nim-red-key", "v"));

        Assert.Equal(3, ManagerCount(manager, "Loaded"));
        Assert.Equal(2, ManagerCount(manager, "AliasHits"));
    }

    // ---- the shipped mapping ------------------------------------------------------------------

    /// <summary>
    /// Every alias the shipped <c>appsettings.json</c> declares points at a configuration key
    /// this application actually reads.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The failure this guards is a typo in a mapping — <c>SentinelAI:Models:Agents:Reperter</c>
    /// — which loads the secret, reports success, and leaves the Reporter with no credential.
    /// Nothing throws, and the boot-time provider check fails with "no key for Reporter" while
    /// the vault log says seven secrets loaded.
    /// </para>
    /// <para>
    /// Checked against the key <em>prefixes</em> the application binds rather than against an
    /// exhaustive list, because an exhaustive list would be a second copy of the configuration
    /// schema and would go stale the first time a section was added.
    /// </para>
    /// </remarks>
    [Fact]
    public void Every_shipped_alias_targets_a_configuration_section_the_application_binds()
    {
        var shipped = new ConfigurationBuilder()
            .SetBasePath(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!)
            .AddJsonFile("appsettings.json", optional: false)
            .Build();

        var aliases = shipped
            .GetSection($"{KeyVaultOptions.SectionName}:SecretNames")
            .GetChildren()
            .ToDictionary(c => c.Key, c => c.Value!);

        Assert.NotEmpty(aliases);

        string[] bound =
        [
            "ConnectionStrings:",
            "Authentication:Jwt:",
            "SentinelAI:Models:",
            "Observability:Tracing:",
            "Knowledge:",
            "Cors:",

            // The Stripe secret key and webhook secret, bound by StripeOptions (Infrastructure).
            // The webhook secret in particular is the only authentication on the one endpoint
            // that can grant a paid plan, so an alias that silently landed nowhere would leave
            // the vault log reporting success while every delivery was rejected.
            "Billing:",
        ];

        Assert.All(aliases, alias => Assert.True(
            bound.Any(prefix => alias.Value.StartsWith(prefix, StringComparison.Ordinal)),
            $"'{alias.Key}' maps to '{alias.Value}', which is not under any section this "
            + $"application binds ({string.Join(", ", bound)})"));
    }

    /// <summary>
    /// The shipped configuration has no vault, so a fresh clone starts without credentials.
    /// </summary>
    /// <remarks>
    /// Asserted on the committed file rather than on a default, because the value that decides
    /// this is the one in the file — the same class of drift as the <c>Provider</c> setting that
    /// was committed as <c>NIM</c> against its own comment and broke a clean checkout.
    /// </remarks>
    [Fact]
    public void The_committed_settings_configure_no_vault()
    {
        var shipped = new ConfigurationBuilder()
            .SetBasePath(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!)
            .AddJsonFile("appsettings.json", optional: false)
            .Build();

        Assert.True(string.IsNullOrWhiteSpace(shipped[$"{KeyVaultOptions.SectionName}:Uri"]));
    }

    // ---- helpers --------------------------------------------------------------------------------

    /// <summary>
    /// A manager over the shipped alias map.
    /// </summary>
    /// <remarks>
    /// <c>SentinelSecretManager</c> is internal to the Api assembly, so it is reached by
    /// reflection rather than by widening its visibility. The type is an implementation detail
    /// of one configuration call; making it public to test it would be letting the test decide
    /// the public surface.
    /// </remarks>
    private static KeyVaultSecretManager Manager()
    {
        var aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["sql-default-connection"] = "ConnectionStrings:DefaultConnection",
            ["jwt-signing-key"] = "Authentication:Jwt:SigningKey",
            ["nim-red-key"] = "SentinelAI:Models:Agents:Red:ApiKey",
        };

        var type = typeof(KeyVaultOptions).Assembly
            .GetType("SentinelAI.Api.Configuration.SentinelSecretManager")
            ?? throw new InvalidOperationException("SentinelSecretManager was renamed or removed");

        return (KeyVaultSecretManager)Activator.CreateInstance(type, aliases.AsReadOnly())!;
    }

    private static int ManagerCount(object manager, string property) =>
        (int)manager.GetType().GetProperty(property)!.GetValue(manager)!;
}

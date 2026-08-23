# Secrets from Azure Key Vault (SEC-35, audit 35-A)

**Code:** `src/SentinelAI.Api/Configuration/`
**Tests:** `tests/SentinelAI.Integration.Tests/Retention/KeyVaultConfigurationTests.cs` (14)

SEC-35's acceptance list ends with "secrets in Azure Key Vault". This is that: a configuration
source layered over the committed settings, opt-in on a vault URI, authenticated with the
Container App's managed identity.

---

## Turning it on

```jsonc
"KeyVault": {
  "Uri": "https://sentinelai-kv.vault.azure.net/",
  "ReloadIntervalMinutes": 0,
  "SecretNames": {
    "sql-default-connection": "ConnectionStrings:DefaultConnection",
    "jwt-signing-key": "Authentication:Jwt:SigningKey",
    "nim-red-key": "SentinelAI:Models:Agents:Red:ApiKey"
  }
}
```

In Azure, set it as an environment variable so nothing needs redeploying to change vault:

```
KeyVault__Uri=https://sentinelai-kv.vault.azure.net/
```

Then grant the Container App's managed identity the **Key Vault Secrets User** role on the vault.
That is the whole credential story — there is no client secret to store, rotate or leak, which is
the point of moving secrets into a vault in the first place.

**Empty `Uri` is off, and off means no client, no credential and no network.** Every test, the
offline demo and a fresh clone run in exactly that state. The committed `appsettings.json` ships
it empty, and there is a test asserting that it does — the same class of drift as the `Provider`
setting that was once committed as `NIM` against its own comment and broke a clean checkout.

## Where it sits in the layering

```
appsettings.json  →  appsettings.{Environment}.json  →  Key Vault  →  environment variables
                                                        ↑ wins over files
```

Last writer wins, so the vault is added **after** the files. A vault that lost to a committed
`appsettings.json` would change nothing — the most expensive kind of no-op, because it looks like
it is working.

Environment variables still override the vault. That is deliberate: it is what makes a local run
or a container debug session possible without touching the vault, and it is the escape hatch when
a rotated secret is wrong.

**The vault is added before `AddInfrastructureServices`, and that ordering is load-bearing.** The
model options, the pricing table and the egress catalog are all read *eagerly*, at registration
time. A vault layered on afterwards would be read by nothing that matters, and `ProviderReadiness`
would still fail the boot on an absent key while the log said seven secrets had loaded.

## Secret names

Two rules, in order.

**1. An explicit alias from `SecretNames` wins.** This deployment's vault predates the convention
below — its secrets are named `sql-default-connection`, `nim-red-key`, `jwt-signing-key`.

**2. Otherwise the standard convention applies**, where a double hyphen is the section separator:

| Vault secret | Configuration key |
|---|---|
| `Authentication--Jwt--SigningKey` | `Authentication:Jwt:SigningKey` |
| `Cors--AllowedOrigins--0` | `Cors:AllowedOrigins:0` |
| `CorpusVersion` | `CorpusVersion` |

Renaming live secrets to suit a convention is a change with an outage in it; declaring the mapping
is not. Both styles work, and a vault holding a mixture — the normal state during a migration — is
handled without configuration beyond the aliases themselves.

### Why the mapping is tested

**The failure mode is silence.** A secret loaded under a key nothing reads does not throw, does
not warn, and leaves the application running on whatever `appsettings.json` said — an empty
signing key, no provider credential. Without the alias, `sql-default-connection` loads as a
configuration key literally called `sql-default-connection`: present, and inert.

A typo in an alias is worse, because it looks like success: `SentinelAI:Models:Agents:Reperter`
loads the secret, the vault log reports seven secrets, and the boot-time provider check fails with
"no key for Reporter" for what reads like an unrelated reason. So there is a test asserting that
every alias in the shipped `appsettings.json` targets a section this application actually binds.

## What the boot log says

One line, every start, because *the most common way a Key Vault integration is wrong is that it is
silently not running*.

```
info: SentinelAI.Secrets  Secrets loaded from key vault https://sentinelai-kv.vault.azure.net/:
                          7 secret(s), 6 resolved through an explicit name mapping, reload off
```

```
info: SentinelAI.Secrets  No key vault configured (KeyVault:Uri is empty); secrets come from
                          configuration files, environment variables and user-secrets
```

```
warn: SentinelAI.Secrets  Key vault … is configured but returned no secrets. The application is
                          running on its committed defaults. This is usually a missing 'Key Vault
                          Secrets User' role assignment on the managed identity rather than an
                          empty vault
```

The third is the one worth having. An empty vault is a legitimate state, so it is not an error —
but it is almost always a permissions problem, and it looks identical to success everywhere else.

## Failure behaviour

| Situation | What happens |
|---|---|
| No `Uri` | No source added. Normal. |
| `Uri` is blank or whitespace | Treated as unconfigured — Container Apps "unsets" a variable by setting it to `""`. |
| `Uri` is not an absolute URI | **Boot fails**, naming the setting and the value. |
| Vault unreachable, or identity unauthorised | **Boot fails**, naming the vault. |

The last one is a deliberate choice. Starting anyway means running on the committed defaults — an
empty JWT signing key, no provider credential, a connection string pointing nowhere — and those
surface later, one at a time, far from the cause. The exception is rethrown with the vault named,
because the underlying message (`ManagedIdentityCredential authentication unavailable`) does not
say which vault, or which setting asked for it.

## Reloading

`ReloadIntervalMinutes` defaults to `0`, which reads the vault once at startup.

Reloading is what makes a rotated secret take effect without a restart. It is also a poll against
a metered service from every instance, so it is a decision a deployment makes rather than one it
inherits.

**Note what reloading does not cover.** The model options, the pricing table, the egress catalog
and the tracing options are read once at registration, so a rotated *model* key reaches them on
the next restart regardless of this setting. What reloading covers is everything read through
`IConfiguration` at request time — the JWT signing key among them, which is read lazily inside the
bearer-token options delegate for exactly this reason.

## Which secrets belong in the vault

From the credential inventory, in rough order of how badly you want them out of a file:

| Vault secret | Configuration key | Why |
|---|---|---|
| `sql-default-connection` | `ConnectionStrings:DefaultConnection` | Carries the SQL password |
| `jwt-signing-key` | `Authentication:Jwt:SigningKey` | Forges any token in the system |
| `nim-{role}-key` | `SentinelAI:Models:Agents:{Role}:ApiKey` | Four keys, one per agent — billable |
| `langfuse-secret-key` | `Observability:Tracing:Langfuse:SecretKey` | Only if tracing is on (SEC-36) |

The CI secret-hygiene job greps for provider key prefixes (`nvapi-`, `sk-ant-`, `sk-`) and for
connection-string passwords. It will **not** catch a Langfuse key or a JWT signing key, so those
two rely on this mechanism rather than on the guard.

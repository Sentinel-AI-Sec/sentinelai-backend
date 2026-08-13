# Configuration

Providers, credentials, the database, and the knobs that change how the debate behaves.

---

## 0. Database

`ConnectionStrings:DefaultConnection` is read by `AddInfrastructureServices` and is required
for migrations and anything touching persistence. **The debate endpoints do not use it** —
`POST /v1/debates` runs with no database at all, which is why a missing connection string
does not stop the API from starting.

It is deliberately **not** set in the committed `appsettings.json`: an empty string makes
`dotnet ef` fail, and a real one does not belong in a tracked file. Set it in one of:

| Location | Use |
|---|---|
| `appsettings.Development.json` | Local development. **Git-ignored.** |
| `ConnectionStrings__DefaultConnection` env var | CI and deployment. |
| `dotnet user-secrets` | Local development, outside the working tree. |

`appsettings.Development.example.json` carries a zero-setup LocalDB default — copy it to
`appsettings.Development.json` and adjust.

```bash
dotnet ef database update --project src/SentinelAI.Infrastructure --startup-project src/SentinelAI.Api
```

> A connection string with a password in a tracked file fails the CI `secrets` job. Use
> integrated auth locally and an environment variable everywhere else.

---

## 1. Providers

The agents are real `ChatClientAgent`s in every configuration. Only the backing
`IChatClient` changes, so switching provider is configuration, never code.

| Provider | Endpoint | Notes |
|---|---|---|
| `Scripted` | — | **Default.** Deterministic offline responses. Every test runs here: no key, no network, no spend. |
| `Nim` | `https://integrate.api.nvidia.com/v1` | NVIDIA NIM. OpenAI-wire-compatible, so it reuses the OpenAI client. |
| `Anthropic` | `https://api.anthropic.com/v1` | For when Claude access lands. |
| `AzureOpenAI` | **must be set explicitly** | The AID-01 production target. See §1.1 — it does not behave like the others. |

Every live provider **fails loud** on a missing key rather than falling back to `Scripted`.
A silent fallback would produce runs that look successful and mean nothing — the same class
of bug as the silent embedding fallback AID-01 §5 exists to prevent.

Since SEC-30 this is checked **at startup**, not at the first model call. A live provider
with a missing key or (for Azure) a missing endpoint refuses to boot, naming the agents that
lack one. Previously the API accepted a scan, stored the bundle and queued the job before
discovering the problem inside a debate turn.

### 1.1 Azure OpenAI

Azure speaks the OpenAI *format* but not the OpenAI *protocol*, and gets its own client for
three reasons — each of which produces a 401 or 404 rather than a useful error if ignored:

| | OpenAI-compatible (`Nim`, `Anthropic`) | `AzureOpenAI` |
|---|---|---|
| Auth | `Authorization: Bearer <key>` | `api-key: <key>` |
| Model | sent in the request body | a **deployment name** in the URL path |
| Version | — | `api-version` query parameter, required |

The practical consequence: under Azure, **`HighTierModel` and `CheapTierModel` are deployment
names, not model names.** Azure has no way to ask for `gpt-4o` by name — you create a
deployment, choose its name, and address that. The defaults (`gpt-4o`, `gpt-4o-mini`) assume
you named the deployment after the model it serves, which is the usual convention. If yours
is called something else, set these to the deployment names.

```jsonc
{
  "SentinelAI": {
    "Models": {
      "Provider": "AzureOpenAI",

      // Your resource URL. No default is possible — the host is your resource name.
      "Endpoint": "https://my-resource.openai.azure.com",

      // Deployment names, not model names.
      "HighTierModel": "gpt-4o",
      "CheapTierModel": "gpt-4o-mini",

      "Agents": {
        "Orchestrator": { "ApiKey": "" },
        "Red":          { "ApiKey": "" },
        "Blue":         { "ApiKey": "" },
        "Reporter":     { "ApiKey": "" }
      }
    }
  }
}
```

A per-agent `Model` is also a deployment name here, which is how one role can be pinned to a
separately-quota'd deployment.

---

## 2. Credentials — one key per agent

Four slots, one per AID-01 agent, so rate limits and spend are isolated per role. With a
provider like NIM that rate-limits per key, a shared key means one agent's retries throttle
the entire debate and the usage dashboard cannot attribute anything.

```jsonc
{
  "SentinelAI": {
    "Models": {
      "Provider": "Nim",

      "HighTierModel": "nvidia/nemotron-3-super-120b-a12b",
      "CheapTierModel": "nvidia/nemotron-3-super-120b-a12b",

      // Optional shared fallback, used by any agent whose own key is blank.
      "ApiKey": "",

      "Agents": {
        "Orchestrator": { "ApiKey": "nvapi-..." },
        "Red":          { "ApiKey": "nvapi-..." },
        "Blue":         { "ApiKey": "nvapi-..." },
        "Reporter":     { "ApiKey": "nvapi-...", "Model": "" }
      }
    },

    "Debate": { "MaxRounds": 3 }
  }
}
```

**Resolution order** for any agent: its own `ApiKey` → the shared `ApiKey` → fail loud
naming the agent that is missing one.

**Per-agent `Model`** overrides the tier default for that role alone. Blank means "use the
tier default". This is how you put adjudication on a different model from assertion.

### Where to put it

| Location | Use |
|---|---|
| `src/SentinelAI.Api/appsettings.Development.json` | The API. **Git-ignored.** |
| `samples/SentinelAI.Agents.Demo/dev.json` | The demo runner. **Git-ignored.** |
| `dotnet user-secrets` | Local development, outside the working tree. |
| Environment variables | CI and deployment. |

Each has a committed `.example` template beside it — copy and fill in.

The committed `appsettings.json` ships `Provider: "Scripted"` so a fresh clone runs with no
credentials at all. `appsettings.Development.json` overrides it to a live provider.

> **Never commit a filled-in secrets file.** `.gitignore` covers them and the CI `secrets`
> job fails the build on a tracked secrets file or an `nvapi-` / `sk-ant-` / `sk-` literal
> anywhere in the tree. A leaked key is not recoverable by reverting the commit — rotate it.

---

## 3. Model tiers

AID-01 §2.1 routes reasoning-heavy turns to a high tier and routine turns to a cheap one.
The shipped policy, in `SentinelAI:Debate:Tiers`:

| Role | Tier | Why |
|---|---|---|
| `Red` | `High` | Chaining — reasoning-heavy. |
| `Blue` | `High` | Link validation — reasoning-heavy, and the false-positive reducer. |
| `Reporter` | `High` | Adjudication — reasoning-heavy. |
| `Orchestrator` | `Cheap` | Briefs Red from the graph and asserts nothing. The routine turn. |

Which model id a tier resolves to is `HighTierModel` / `CheapTierModel` (§1), per provider.
Overriding a role is a config change:

```json
"SentinelAI": { "Debate": { "Tiers": { "Reporter": "Cheap" } } }
```

Whatever the map says, **the tier that actually served a turn is stamped on that turn** and
shows up in the audit's cost breakdown — see [Cost_Tracking.md](Cost_Tracking.md). Reading
the policy back out of configuration would describe what the settings say now rather than
what ran.

---

## 3.1 Token prices

`SentinelAI:Models:Pricing` turns measured tokens into money. Rates are per **million**
tokens, quoted separately for input and output because every provider prices them
differently.

```json
"SentinelAI": {
  "Models": {
    "Pricing": {
      "Currency": "USD",
      "High":  { "InputPerMillionTokens": 2.50, "OutputPerMillionTokens": 10.00 },
      "Cheap": { "InputPerMillionTokens": 0.15, "OutputPerMillionTokens": 0.60 }
    }
  }
}
```

Nothing needs to be set for Azure, Anthropic or Scripted: published list prices are built
into `ProviderPricing` and used per tier when configuration supplies none. Configuration wins
where it is present, which is what negotiated rates and repriced models need.

**NIM ships no default**, because its price depends on how it is hosted. Its tokens are still
counted; the audit reports them with `rated: false` and a total of zero, which means *"we do
not know what this cost"* rather than *"this was free"*. Set the two `High`/`Cheap` blocks
above to price it. Full behaviour in [Cost_Tracking.md](Cost_Tracking.md).

---

## 4. Debate options

| Option | Default | What it does |
|---|---|---|
| `MaxRounds` | `3` | The turn-cap. Red+Blue exchange at most this many rounds before the Reporter adjudicates regardless. Guarantees termination. Values below 1 are rejected. |
| `MaxOutputTokens` | `4000` | Per-turn output ceiling. **Must clear the model's reasoning preamble** — see below. |
| `Temperature` | low | Adversarial reasoning over a fixed graph, not creative writing. Lower also shortens responses. |

### Sizing `MaxOutputTokens`

Reasoning models narrate before answering, and that narration comes out of the same budget.
At 900 tokens, a live run had Blue spend the entire budget on scratchpad and truncate before
writing its verdict — which the parser then read as a converged debate. See
[Live_Model_Findings.md §2–3](Live_Model_Findings.md).

Budget for the reasoning *and* the answer. Terse instructions do the real shortening; this
cap only stops a runaway.

---

## 5. Running against a live model

```bash
dotnet run --project samples/SentinelAI.Agents.Demo -- debate --provider nim
```

`--provider` accepts `scripted | nim | anthropic | azureopenai` and overrides the configured
value. Omit it and configuration decides.

Only the `debate` scenario is meaningful live — `turncap`, `resume` and `unresolved` force a
specific failure that a real model will not reproduce on demand.

Expect **90–140 seconds** for a live run: the calls are sequential and non-streaming, so
nothing prints while an agent is thinking. The spinner shows it is alive. See
[Live_Model_Findings.md §6](Live_Model_Findings.md) for measured latency.

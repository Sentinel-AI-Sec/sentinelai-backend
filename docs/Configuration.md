# Configuration

Providers, credentials, and the knobs that change how the debate behaves.

---

## 1. Providers

The agents are real `ChatClientAgent`s in every configuration. Only the backing
`IChatClient` changes, so switching provider is configuration, never code.

| Provider | Endpoint | Notes |
|---|---|---|
| `Scripted` | — | **Default.** Deterministic offline responses. Every test runs here: no key, no network, no spend. |
| `Nim` | `https://integrate.api.nvidia.com/v1` | NVIDIA NIM. OpenAI-wire-compatible, so it reuses the OpenAI client. |
| `Anthropic` | `https://api.anthropic.com/v1` | For when Claude access lands. |
| `AzureOpenAI` | **must be set explicitly** | The AID-01 production target. |

Every live provider **fails loud** on a missing key rather than falling back to `Scripted`.
A silent fallback would produce runs that look successful and mean nothing — the same class
of bug as the silent embedding fallback AID-01 §5 exists to prevent.

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
| `samples/SentinelAI.Agents.Demo/dev.json` | Local development. **Git-ignored.** |
| `dotnet user-secrets` | Local development, outside the working tree. |
| Environment variables | CI and deployment. |

`dev.example.json` is the committed template — copy it to `dev.json` and fill it in.

> **Never commit `dev.json`.** `.gitignore` covers it and the CI `secrets` job fails the
> build on a tracked secrets file or an `nvapi-` / `sk-ant-` / `sk-` literal anywhere in the
> tree. A leaked key is not recoverable by reverting the commit — rotate it.

---

## 3. Model tiers

AID-01 §2.1 routes reasoning-heavy turns to a high tier and routine turns to a cheap one.

```csharp
Tiers[AgentRole.Red]      = ModelTier.High;
Tiers[AgentRole.Blue]     = ModelTier.High;
Tiers[AgentRole.Reporter] = ModelTier.High;
```

All three default to high because chaining, link validation and adjudication are all
reasoning-heavy. The cheap tier is wired and available for routine formatting work added
later.

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

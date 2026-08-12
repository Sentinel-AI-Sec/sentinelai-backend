# LLM provider abstraction (SEC-30)

The debate agents must never know which AI vendor they are talking to. Changing from Azure
GPT-4o to Claude is editing a config file, not editing C# — and that claim has to be proven
by a test that actually runs a debate, not asserted in a comment.

Source of truth is the code. This page is a map of it.

---

## 1. What was already there, and what this task added

SEC-02 built the seam: `IChatClientFactory` returns an `IChatClient`, and every agent is a
`ChatClientAgent` over one. That part was genuinely done, and this task did not rebuild it.

What SEC-30 found missing was **proof and correctness**, not structure:

| SEC-30 step | Before | After |
|---|---|---|
| 1. LLM behind the connector abstraction | Done (SEC-02) | unchanged |
| 2. Two providers selectable by config | Azure declared but **could never authenticate** | Azure built on `AzureOpenAIClient`, wire format asserted |
| 3. No agent code references a provider | True by discipline, unenforced | `ProviderIsolationTests` makes it an invariant |
| 4. Integration test runs the debate on the other provider | **Did not exist** | `ProviderDebateTests` — full debate, per provider, config-driven |
| 5. Config change switches provider | unproven | asserted end to end |

Plus one gap the ticket did not name: a live provider with a missing key failed at the first
model call, not at startup. §5.

---

## 2. The seam

```
DebateEngine.RunAsync(brief)
   │
   ▼
DebateWorkflow.Build(IChatClientFactory, DebateOptions)
   │  for each of Orchestrator / Red / Blue / Reporter:
   │     tier   = options.TierFor(role)          ← policy: High or Cheap
   │     client = clients.Create(role, tier)     ← THE ONLY provider decision in the system
   │     new ChatClientAgent(client, instructions, name)
   ▼
ChatClientFactory.Create(role, tier)
   │
   ├─ Scripted     → ScriptedChatClient(role)              offline, deterministic
   ├─ Nim          ┐
   ├─ Anthropic    ┴→ OpenAIClient  → Bearer auth, model in body
   └─ AzureOpenAI   → AzureOpenAIClient → api-key header, deployment in path, api-version
```

Everything above `Create()` is vendor-blind. Everything below it is vendor detail. The whole
task is about keeping that line honest.

---

## 3. File-by-file

### Infrastructure

| File | What changed |
|---|---|
| `Agents/Providers/ChatClientFactory.cs` | Azure split onto its own `AzureOpenAIClient` branch; shared `RequireKey` so every provider reports a missing credential identically; optional `PipelineTransport` seam (§4) |
| `Agents/Providers/ProviderReadiness.cs` | **New.** Startup preflight — can this provider actually serve a debate? |
| `Agents/Providers/ModelProviderOptions.cs` | Documents that `HighTierModel`/`CheapTierModel` are *deployment names* under Azure |
| `Agents/DependencyInjection.Agents.cs` | Calls `ProviderReadiness.Verify` during registration |
| `SentinelAI.Infrastructure.csproj` | `Azure.AI.OpenAI` 2.1.0 |

### Tests

| File | What it covers |
|---|---|
| `Agents/ProviderDebateTests.cs` | 7 tests. **The acceptance criterion.** A full debate driven only by a configuration dictionary, on Scripted / Anthropic / Azure, plus tier routing and per-agent keys reaching the provider. |
| `Agents/AzureProviderTests.cs` | 7 tests. The Azure wire format: deployment in the path, `api-version`, `api-key` header — and the contrast case proving an OpenAI-compatible provider still uses Bearer. |
| `Agents/ProviderIsolationTests.cs` | 4 tests. Reflection guard: no type in `Agents.Executors` or `Agents.Orchestration` references a provider — including a self-test proving the guard has teeth. |
| `Agents/ProviderReadinessTests.cs` | 8 tests. The preflight, including "one agent missing a key is still a failure". |
| `Agents/FakeProviderServer.cs` | **New.** A stand-in OpenAI-wire provider — real HTTP, answers in character per agent, records every request. |

### Docs

`docs/Configuration.md` §1.1 (Azure's three protocol differences),
`appsettings.Development.example.json` (commented Azure block).

---

## 4. How a live provider is tested without a network

This is the part that makes the acceptance criterion real, so it is worth explaining.

`ProviderSwitchTests` (SEC-02) constructs clients and checks their *type*. It never calls one,
because calling one needed a real endpoint and a real key. That is precisely how the Azure
branch stayed broken for a sprint: every test it had passed.

`ChatClientFactory` now takes an optional `PipelineTransport`. Production passes nothing. The
tests pass a `FakeProviderServer` — an `HttpMessageHandler` wrapped as a transport, so the
entire real client stack sits above it:

```
ChatClientAgent → IChatClient → OpenAI/Azure client → retry policy → HTTP pipeline
                                                                        │
                                                          FakeProviderServer (no socket)
```

Everything the factory does is therefore exercised: credential resolution, endpoint shaping,
deployment naming, model id, retry policy, and the translation of the provider's JSON back
into a debate turn. The fake reads the agent's instructions out of the request body and
answers in character, so a whole Red → Blue → Reporter debate converges over it.

It matches the **full** `"You are the X agent"` opening rather than just the role name — the
Orchestrator's instructions mention the Red Team agent, so a looser match routes the
Orchestrator's own call to Red and the debate answers the wrong thing.

An `HttpMessageHandler` rather than a hand-written `PipelineTransport` because
System.ClientModel already adapts one, and adapting keeps the real header and URI construction
inside the test instead of stubbing it out — which is exactly what needs asserting.

---

## 5. Failing at boot instead of mid-debate

`ProviderReadiness` runs during `AddDebateServices`. If a live provider is configured with a
missing key — or Azure with no endpoint — the host refuses to start and the message names the
agents that lack one and the settings that would supply them.

The failure this replaces was expensive because everything before it looked healthy: the API
started, `POST /v1/scans` answered `202 Accepted`, the bundle was written to disk and the job
row committed — and only then did the missing key surface inside a debate turn, after the
caller had been told the scan was accepted. Every fact needed to refuse was already in
configuration before the host finished booting.

`Scripted` is always ready, which is what lets a fresh clone run with no credentials.

---

## 6. Verifying it

```bash
dotnet test SentinelAI.slnx --filter Provider
```

42 tests — the 26 added here plus SEC-02's 16 `ProviderSwitchTests`, which still pass
unchanged against the refactored factory. Then the whole suite:

```bash
dotnet test SentinelAI.slnx
```

### Mapping to the acceptance criterion

> **Config change → provider switches; debate runs unchanged (integration test asserts).**

| Half of the claim | Proved by |
|---|---|
| "config change" | `ProviderDebateTests` builds every run from an in-memory configuration dictionary. No test names a provider in code — only as a string in config. |
| "provider switches" | `The_same_debate_runs_on_a_live_openai_wire_provider` asserts the fake provider actually received the calls, so it cannot have silently fallen back to Scripted. |
| "debate runs unchanged" | `Switching_provider_by_configuration_alone_changes_nothing_about_the_debate` runs two providers and compares agent order, turn count, convergence and termination path. |
| "no agent code references a provider" | `ProviderIsolationTests`, enforced by reflection rather than by review. |

### What the isolation guard does and does not catch

It inspects the type *surface* of every type in the agent namespaces — base types, interfaces,
fields, properties, constructor and method signatures, generic arguments, and method local
variables. That covers every realistic route to a provider, because to compare against
`ModelProvider` a type must first hold or receive `ModelProviderOptions`.

It would not catch a comparison built entirely from constants the compiler inlines.
`The_guard_detects_a_violation` demonstrates the guard's reach against a deliberately
offending type rather than leaving it assumed — a guard that can only ever pass is not a guard.

The rule is deliberately narrower than "agents may not touch the Providers namespace": they
*must* reference `IChatClientFactory`, since that is the abstraction. What they may not know
is what the factory builds. **The workflow may know a factory exists; it may not know that
Anthropic does.**

---

## 7. Known gaps

- **No live-credential smoke test.** Everything here runs offline. Correct wire *shape* is
  proven; that a real Azure resource accepts it is not, and cannot be without a key in CI.
  If you get one, the highest-value addition is a single opt-in test, skipped unless an
  environment variable is present.
- **`api-version` is the SDK default.** `AzureOpenAIClientOptions` picks it; it is not
  configurable through `SentinelAI:Models`. Pinning it is a one-line addition if a specific
  version is ever needed.
- **Anthropic runs through an OpenAI-compatible gateway,** not Anthropic's native API. That is
  the SEC-02 design and it works, but native `/v1/messages` would need its own branch —
  the same shape as the Azure one.
- **The tier map is provider-independent by design.** `DebateOptions.Tiers` says Red is a
  High-tier turn; what "High" costs differs per provider. Nothing compares spend across
  providers, so a switch changes cost silently.

# Model-tier routing & cost tracking (SEC-31)

Send hard thinking to the expensive model and routine work to the cheap one, and record what
each scan cost. Two model tiers already existed as a setting after SEC-02; what this task
added is that the choice is **recorded**, the tokens are **counted**, and the money is
**stored** — including the cases where the money is not knowable.

Source of truth is the code. This page is a map of it.

---

## 1. What was already there, and what this task added

| SEC-31 step | Before | After |
|---|---|---|
| 1. Define two tiers behind the connector | Done (SEC-02/30): `ModelTier`, `HighTierModel`/`CheapTierModel` | unchanged |
| 2. Route each turn by kind | Role→tier map existed; nothing proved it, and an unmapped role silently became `High` | Map documented and pinned by test; fallback is the shipped default; the tier is stamped on the turn it served |
| 3. Record tokens and cost per scan, by tier | **Nothing was counted at all** | `TokenUsage` on every turn, folded into `AuditCost` by `CostAccounting` |
| 4. Expose the cost figure on the audit record | — | `DraftAudit.Cost`, the `Reports` cost columns, and `cost` on the debate response |
| 5. Test: a completed audit shows a cost per tier | — | `CostTrackingTests`, over a provider that returns a real `usage` block |

Plus one thing the ticket did not name: **the Orchestrator's briefing is a billed model call
that is deliberately not a debate turn**, so an audit measured from the transcript alone
under-reports every scan by one call. §4.

---

## 2. The path

```
DebateWorkflow.Build(clients, options, pricing)
   │  tier = options.TierFor(role)            ← resolved ONCE per role…
   │  client = clients.Create(role, tier)     ← …used to pick the model…
   │  executor = new RedTeamExecutor(agent, tier)   ← …and carried onto the turn
   ▼
DebateExecutor.RunTurnAsync
   │  response = agent.RunAsync(prompt)
   │  turn with { Tier, Usage = UsageOf(response) }   ← the provider's own token counts
   ▼
DebateState.Transcript  (+ .Seed for the Orchestrator)    ← serialized into every checkpoint
   ▼
ReporterExecutor.BuildAudit
   │  CostAccounting.Measure(state.AllTurns, pricing)
   ▼
DraftAudit.Cost ──► ReportBuilder.Bill ──► Reports.HighTier*/CheapTier*  (persisted)
                └─► DebateResponse.Cost                                   (HTTP)
```

The tier is resolved once and then travels with both the client and the executor. Asking the
policy twice is how the model that answered and the tier the audit bills could drift apart,
and a bill is only evidence if it names what actually ran.

---

## 3. Three ways to spend nothing

A total of zero has three different meanings, and a number that cannot tell them apart is
worse than no number:

| Case | `Measured` | `FullyRated` | `Total` |
|---|---|---|---|
| No model call reached a provider | `false` | `true` | `0` |
| Provider served turns but reported no `usage` | `false` | `true` | `0` |
| Tokens spent on a tier with no configured rate | `true` | **`false`** | `0` |
| The offline `Scripted` provider — genuinely free | `true` | `true` | `0` |

The third row is the one that matters. NIM ships no list price because its rate depends on
how it is hosted, so its tokens are counted and its money is *not claimed*. Reporting that as
`$0.00` with no qualifier would be the same failure mode AID-01 §5 forbids for the embedder:
a plausible-looking number produced by a path that silently gave up.

`Rated` is carried per tier, stored on the report (`CostRated`), and surfaced on the wire.

---

## 4. Why the Orchestrator's briefing needed somewhere to live

Round 0 seeds shared state but is not a debate turn: counting it in the transcript would
inflate `TurnCount` and every round number derived from it. But when the Orchestrator is
model-backed it makes a real call — and under the shipped policy it is the *only* call on the
cheap tier, so dropping it would leave the entire tier missing from most breakdowns.

`DebateState.Seed` holds it, off to the side of the transcript. `AllTurns` is what the
accounting folds over. The pass-through orchestrator (tests only, no model) stores nothing,
because a seed recorded there would appear in the breakdown as a call that never happened.

---

## 5. Why the count lives on the turn

The obvious design is a counter the run increments — a delegating `IChatClient` writing into
a ledger. It does not survive `DebateRunner.ResumeAsync`.

A resumed debate restores completed turns from the checkpoint rather than re-running them, so
a fresh in-memory ledger would count only what happened *after* the interruption and report a
long debate as a cheap one. `TokenUsage` on `DebateTurn` is part of `DebateState`, which is
what the framework serializes into every checkpoint, so the tokens come back with the turns.
`Cost_survives_a_resume_from_checkpoint` pins exactly that.

---

## 6. Where the money comes from

`ProviderPricing` is the only vendor-aware part of this feature, and it sits beside the other
vendor detail on purpose. Everything above it — `ModelPricing`, `CostAccounting`, the audit,
the executors — names no provider.

Resolution order, per tier: `SentinelAI:Models:Pricing:<Tier>` → built-in list price for the
configured provider → **unrated**. Each tier is read by name rather than bound as an
enum-keyed dictionary, for the reason `ModelOptionsLoader` gives: the binder swallows a
misspelt key, and a rate that silently fails to load is indistinguishable from one nobody
entered. A half-configured rate (input but not output) is rejected rather than billing output
at zero.

The built-in numbers are list prices at the time of writing. They are a convenience, not a
source of truth — vendors reprice, and negotiated rates are something else entirely. For
Azure they are the prices of the *models* the tier defaults name; a deployment named after a
different model is priced wrong. Configuration is the fix in both cases.

---

## 7. Storage

Six columns plus a currency, a call count and `CostRated`, flattened onto `Reports`
(`AddAuditCostToReport`). There are exactly two tiers, fixed by `ModelTier`, and one report
per scan — a child table would buy nothing and cost a join on every read.

`decimal(18,6)`, not SQL Server's default `decimal(18,2)`: a whole debate is a handful of
calls of a few thousand tokens, so at list prices it costs **cents**. At two decimal places
every scan rounds to `0.00` and the metric this task exists to produce reads as free. Stored
and wrong is worse than not stored.

---

## 8. What the API returns

`POST /v1/debates` now closes with:

```json
"cost": {
  "currency": "USD",
  "total": 0.00110,
  "modelCalls": 4,
  "totalTokens": 120,
  "rated": true,
  "measured": true,
  "byTier": [
    { "tier": "High",  "calls": 3, "inputTokens": 30, "outputTokens": 60, "cost": 0.00099, "rated": true },
    { "tier": "Cheap", "calls": 1, "inputTokens": 10, "outputTokens": 20, "cost": 0.00011, "rated": true }
  ]
}
```

Each turn in the transcript also carries its `tier` and `tokens`, so a reader can see the
routing decision that produced the breakdown rather than having to trust it.

---

## 9. Verifying it

```bash
dotnet test SentinelAI.slnx --filter "FullyQualifiedName~Cost|FullyQualifiedName~TierRouting"
```

| Test file | What it covers |
|---|---|
| `Application.Tests/Debate/CostAccountingTests.cs` | The arithmetic and the honesty rules: grouping, input/output priced apart, absent ≠ zero, unrated ≠ free, stable ordering. |
| `Application.Tests/Debate/TierRoutingTests.cs` | The shipped policy — reasoning roles High, briefing Cheap — and that a role dropped from the map keeps its shipped tier rather than becoming expensive. |
| `Application.Tests/Reporting/ReportCostTests.cs` | The figures survive onto the persisted report, `CostRated` included. |
| `Integration.Tests/Agents/CostTrackingTests.cs` | The acceptance criterion, end to end: a debate over a provider returning a real `usage` block, priced from configuration, split by tier — plus re-routing, the briefing call, the unpriced provider, and resume. |

`ProviderDebateTests.Tier_routing_survives_the_switch_to_a_live_provider` (SEC-30) is the
other half of routing: it asserts the tier reached the **provider** as a different model id.
This page's tests assert the tier was recorded on the **turn**. Either alone can pass while
spend is attributed to the wrong tier.

Offline runs measure tokens too — `ScriptedChatClient` reports an estimate on the usual
four-characters-per-token rule so the accounting path is exercised without a credential. The
estimate cannot turn into invented money: the `Scripted` provider's rate is a real zero,
because nothing leaves the process.

---

## 10. Known gaps

- **Nothing budgets or alerts.** Cost is recorded, not enforced. A per-tenant spend cap is a
  different task and would belong at the point a scan is accepted, not at the point it is
  billed.
- **Rates are per tier, not per model.** A per-agent `Model` override (SEC-02) changes which
  model answers without changing which rate it is billed at. Configure the tier's rate to
  match the model you actually pointed it at.
- **No cross-provider comparison.** Each provider is billed at its own rates and nothing
  aggregates across them, so "is Azure cheaper than Anthropic for this scan" is still a
  question you answer by hand. This is the SEC-30 gap narrowed, not closed.
- **Retries are billed as one turn.** `DebateRetryPolicy` may repeat a failed call; only the
  usage on the successful response is reported, because that is all the provider hands back.
  Failed attempts on some providers are still billed.
- **The read API does not surface it yet.** The columns are populated; SEC-40's endpoints are
  where a screen will read them from.

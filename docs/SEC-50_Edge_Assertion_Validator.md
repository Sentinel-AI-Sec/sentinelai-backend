# SEC-50 · Mechanical edge-assertion validator (anti-hallucination backstop)

**Status:** implemented, unit/decorator-verified (176 tests passing), **not yet run through
`Integration.Tests`** — blocked by a file lock from a running `dotnet watch` instance for the
entire duration of this work, including the revision below. Everything below is accurate as of
the code on `feature/sec-50-edge-assertion-validator`, branched off `dev` at `9e57ac7`.

**For review:** this doc exists so the design and the five live failures it was built against
can be checked independently, and so any further gaps can be scoped properly rather than bolted
on mid-conversation. Section 6 lists what's still open.

**Revision note:** this doc originally covered four live cases and a single `EdgeIntegrityWarnings`
field. A fifth live case (§1, case 5) exposed that treating every hop anywhere in the transcript
as equally load-bearing was itself a precision bug — it would have capped a genuinely valid,
fully-grounded chain because of reasoning the Reporter had already discarded. §2.4 and §3 now
describe the corrected design: warnings are split by whether they're in the chain the Reporter
actually reported, or only in abandoned Red/Blue reasoning.

---

## 1. The problem, found live, not hypothesized

While manually testing `POST /v1/debates` and `POST /v1/scans/{id}/audit` against a real NIM
provider, five distinct cases turned up. Four are the debate asserting a hop that does not
correspond to any real edge; the fifth is different — the *check itself* being too blunt about
what counts as "the chain."

### The five cases

| # | What was asserted | What the graph actually says | Who missed it |
|---|---|---|---|
| 1 | `N3 -> assumes -> N69` | `N69 --assumes--> N3` (reversed) | Blue confirmed it: *"CONFIRMED, edge exists in given edges"* |
| 2 | Red trails off (`N4 -> deployed-as -> (no direct edge, but)`), Blue "completes" it as `N4 -> deployed-as -> N69` | No edge from `N4` to anything — `N4` is `image:tinyapp/order`, a leaf | Blue invents the pairing; the Reporter repeats it verbatim as the chain's own citation |
| 3 | `N4 -> used-by -> N8` | No edge in either direction | Blue confirms it via an invalid transitive argument: *"edge N8-->N1 exists, and N1-->N4 exists, implying N4 is used by N1, and thus N8 is used by N4 through N1"* — chaining two real edges into a fabricated third. (The same pair was **correctly refuted** in an earlier, separate run — same model, different outcome.) |
| 4 | `N65 -> used-by -> N23` and `N65 -> used-by -> N39` | `N23 --used-by--> N65` and `N39 --used-by--> N65` (both reversed) | Blue confirmed both |
| 5 | Red asserted **two** candidate paths in one turn — one repeating `N4 -> used-by -> N8` (same fabrication as case 3), one entirely real. Blue never addressed the fabricated path at all, yet returned `CHAIN_HOLDS`; the Reporter reported only the real path. | The *reported* chain was completely clean. | Not a model failure this time — the mechanical check itself, which (before this fix) scanned Red's *entire* turn and would have capped a valid chain at `Asserted` for reasoning nobody acted on. |

Case 3 matters beyond its own bug: the identical node pair was refuted once and confirmed once by
(presumably) the same model on different runs. That is non-determinism, not a capability gap — no
amount of model upgrading removes the need for a deterministic check, it only changes how often
the check has to catch something.

Case 5 matters differently: it's a **false positive in the safety net itself**, found by a user
deliberately stress-testing the just-shipped fix rather than by a new model failure. It's the
reason §2.4's design changed mid-implementation — see the revision note above.

A related, separate observation surfaced during the same testing, alongside a second, narrower
parsing bug the case-5 investigation exposed:

- `POST /v1/scans/{id}/audit` and `POST /v1/debates` occasionally returned `"Debate ... ended
  without an audit. 0 turn(s) completed"` with no further information. That turned out to be a
  real NIM rate limit (`HTTP 503, ResourceExhausted: Worker local total request limit reached
  (17/16)`) — but the actual exception was being silently discarded by the workflow runner before
  the fix in §5.
- The Reporter's case-5 turn wrote `Chain confirmed: N8 -> N1 -> N69 -> N3 -> N65, N66` — a
  comma-separated list of two branch targets from `N3`, not a hop from `N65` to `N66`. The
  original token-pairing treated every two consecutive `N<i>` references on a line as an asserted
  hop regardless of what separated them, which would have read that comma as an edge nobody
  claimed — the check fabricating a finding of its own. Fixed alongside case 5: a pair is only a
  candidate hop when the text between the two references contains `->`.

---

## 2. Design

### 2.1 What it checks, and deliberately does not check

Two independent, narrow, deterministic checks — nothing that requires understanding what a hop
*means*, only what it *claims to be a fact about*:

1. **Edge existence & direction.** Does the node pair a hop names correspond to a real edge, in
   the asserted direction, the reverse direction, or neither?
2. **Node identity.** Does an inline annotation like `N65:code:orderapp` name the node the brief
   actually declared `N65` to be?

Explicitly **not** attempted: parsing or verifying the asserted *technique* or *evidence* text
(free prose, no ground truth to check it against), and deciding a chain is fake outright — a hop
the check cannot classify is *reported*, not discarded, the same posture `GraphDecorator` and
`AttackGraphHandoff` already take elsewhere in this codebase (refuse to invent, surface rather
than hide). Nor does either check treat two node references as connected unless an arrow actually
joins them in the text (§1, the case-5 comma-list bug) — the check does not get to fabricate a
claim nobody made just because two node numbers appear near each other.

### 2.2 Ground truth is the brief text, not the database

`POST /v1/debates` takes the resource graph as free text from a caller with no persisted
`GraphEdge` row behind it at all. Parsing the "Edges: ..." / "Nodes: ..." sections
`ScanBriefRenderer` already writes — the same text the model itself reads — is what lets one
check cover every caller of `IDebateEngine` uniformly, instead of requiring a database lookup
that only one of the two callers can satisfy.

### 2.3 Where it runs

An `IDebateEngine` decorator, same shape and same registration pattern as the existing
`RedactingDebateEngine` (SEC-33) — wrapped once at DI registration, so every caller gets it
without needing to know it exists or remember to invoke it:

```
IDebateEngine  =  EdgeIntegrityDebateEngine( RedactingDebateEngine( DebateEngine ) )
```

It inspects the **last Red turn, the last Blue turn, and the Reporter's closing turn** — not
earlier rounds (an earlier assertion getting broken is the debate working correctly, not
something to flag). Blue was added after case 2 above showed Red-and-Reporter-only isn't enough:
Blue can introduce a fabrication that never gets restated by the Reporter, and checking only what
the Reporter repeats would miss it at the source.

### 2.4 Reported-chain warnings vs. abandoned-reasoning warnings

Case 5 (§1) showed that not every hop in the transcript deserves equal weight. Red can — and did,
live — assert multiple candidate paths in one turn; the Reporter chooses which one to report and
silently drops the rest. Findings are therefore split into two `DraftAudit` fields, computed by
checking the Reporter's own closing turn **separately** from Red's and Blue's:

- **`EdgeIntegrityWarnings`** — findings **in the text the Reporter actually reported**. This is
  what a reader is being asked to trust, and what `ChainOutcomeWriter` reads.
- **`AbandonedReasoningWarnings`** — the same two checks run over Red's and Blue's turns, minus
  anything already caught in the reported text. Reasoning that was considered and discarded
  before the Reporter ever wrote its output — informational, not a defect in the reported chain.

A finding already present in the reported text is never duplicated into the abandoned list, even
if Red or Blue also stated it.

### 2.5 What a warning does and does not do

- **Never overrides `DraftAudit.Outcome` or `WeakestJoin`.** This is additive information, not a
  second verdict silently replacing the debate's own. The check doesn't know *why* a hop is
  wrong, and downgrading `Converged` to `ChainBroken` outright would claim a certainty the check
  doesn't have.
- **Only `EdgeIntegrityWarnings` caps `ChainOutcomeWriter`'s promotion.** A converged debate with
  a reported-chain warning is written as `Asserted`, never `Validated`. A `ChainBroken` outcome
  stays `Rejected` regardless — already the worst state. `AbandonedReasoningWarnings` never
  affects the chain's status, by design (§2.4) — that's precisely what case 5 required fixing.
- **Both surface in the persisted report**, in separate, clearly labelled blocks —
  `MECHANICAL EDGE CHECK` for reported-chain issues, `NOTE` for abandoned reasoning — appended to
  `Report.Summary` between the debate's own summary and the standing disclaimer, so a human
  reviewer sees both without a separate field to remember to check, and without confusing one for
  the other.

---

## 3. What changed

### New files

| File | Purpose |
|---|---|
| `src/SentinelAI.Application/Debate/EdgeAssertionValidator.cs` | Pure, static. `Validate` (edge existence/direction) and `ValidateNodeLabels` (node identity), both text-in/text-out, no I/O. |
| `src/SentinelAI.Application/Debate/EdgeIntegrityDebateEngine.cs` | The `IDebateEngine` decorator. Checks the Reporter's turn separately from Red's and Blue's (§2.4) and attaches both result sets to the returned `DraftAudit`. |
| `tests/SentinelAI.Application.Tests/Debate/EdgeAssertionValidatorTests.cs` | 21 tests — unit-level, including all five live transcripts reproduced verbatim as regressions, plus the comma-list false-positive case. |
| `tests/SentinelAI.Application.Tests/Debate/EdgeIntegrityDebateEngineTests.cs` | 9 tests — decorator-level, including the Blue-only, label-mismatch, and reported/abandoned split cases. |

### Modified files

| File | Change |
|---|---|
| `src/SentinelAI.Domain/Models/DraftAudit.cs` | New `EdgeIntegrityWarnings` (reported-chain) and `AbandonedReasoningWarnings` (informational) fields, both `IReadOnlyList<string>`, default `[]`. |
| `src/SentinelAI.Infrastructure/Agents/DependencyInjection.Agents.cs` | `IDebateEngine` registration now wraps `EdgeIntegrityDebateEngine` around the existing `RedactingDebateEngine`. |
| `src/SentinelAI.Application/Features/Scan/Graph/ChainOutcomeWriter.cs` | `StatusFor` caps `Validated` to `Asserted` when `EdgeIntegrityWarnings` (only) is non-empty. |
| `src/SentinelAI.Application/Features/Scan/Reporting/ReportBuilder.cs` | Appends two blocks to `Report.Summary` when non-empty: `MECHANICAL EDGE CHECK` (reported-chain) and `NOTE` (abandoned reasoning). |
| `tests/SentinelAI.Integration.Tests/Scan/Graph/ChainOutcomeWriterTests.cs` | Two new cases: converged-with-warnings caps at `Asserted`; broken-with-warnings stays `Rejected`. **Not yet run** — see §6. |
| `src/SentinelAI.Infrastructure/Agents/Orchestration/DebateRunner.cs` | Separate, related fix — see §5. |
| `src/SentinelAI.Infrastructure/Agents/Orchestration/DebateEngine.cs` | Separate, related fix — see §5. |

---

## 4. Evidence the design generalizes, not just fits five cases

After the first design extension (checking the Reporter's turn, prompted by case 2), the next
**two** new live failures (cases 3 and 4) were caught by the existing code with **zero further
changes** — only new regression tests. Case 3 used a different relation (`used-by` vs `assumes`)
and a different fabrication mechanism (transitive chaining vs. direct assertion); case 4 used
different nodes entirely.

Case 5 is a different kind of signal: it's the check producing a **false positive**, caught by a
user deliberately trying to break the fix rather than by another model failure. That's arguably
more valuable than another confirmed catch — it's the difference between "does this detect real
problems" and "does this avoid inventing fake ones," and only the second question guards against
the check itself becoming a liability once it's deployed against real traffic.

The Blue-direct-check and node-identity-check (§2.3, §2.1) were added as scoped follow-ups, not
because a live failure demanded them — they close gaps that were reasoned about, not observed.
That distinction matters for review: cases 1–5 are proven against real model output (or, for
case 5, real check *behavior*); the Blue-direct-check and identity-check are unit-tested against
constructed cases only, since no live transcript happened to exercise them yet.

---

## 5. Related, separate fix: silent failure swallowing

Not part of SEC-50's original scope, but found while chasing case 3's live testing and worth
documenting alongside it. `DebateRunner.CollectAsync` drains the underlying
`Microsoft.Agents.AI.Workflows` event stream and only ever handled two event types
(`AgentTurnEvent`, `WorkflowOutputEvent`). The library has two more, confirmed by reflecting on
`Microsoft.Agents.AI.Workflows.dll` directly:

- `ExecutorFailedEvent` — carries the real `Exception` (typed as `.Data`) from a failed executor,
  plus `.ExecutorId` naming which one.
- `WorkflowErrorEvent` — carries a workflow-level `.Exception`.

Neither was handled. A failed model call (bad key, network error, **rate limit** — this is what
was actually happening) surfaced only as `"Debate ... ended without an audit. 0 turn(s)
completed; 0 checkpoint(s) available for resume."` — the real exception thrown away with no trace
of it anywhere.

**Fixed:** `DebateResult` gained a `Failures: IReadOnlyList<string>` field, populated from both
event types; `DebateEngine.RunAsync`'s exception message now includes them. Confirmed working
against a real failure during this session:

```
Failure(s) reported by the workflow: executor 'reporter' failed:
System.ClientModel.ClientResultException: HTTP 503 (Service Unavailable)
ResourceExhausted: Worker local total request limit reached (17/16)
```

That is a genuine NIM rate limit on the API key in use, not a defect in the pipeline — but before
this fix, every one of the "0 turns" failures hit during this session's testing was
indistinguishable from an actual bug.

---

## 6. Open items — for review, not yet resolved

1. **`Integration.Tests` unverified.** `ChainOutcomeWriterTests`'s two new cases, and the full
   pipeline path through `ThinSlicePipeline` → `ChainOutcomeWriter` → `ReportBuilder`, have not
   been run — the `SentinelAI.Api` build output was continuously locked by a running `dotnet
   watch` process for the entire duration of this work, including the case-5 revision. Everything
   else (176 tests) is Application-layer/decorator-level only.
2. **The reported/abandoned split trusts the Reporter's own text as the definition of "reported."**
   If the Reporter writes a terse summary that doesn't restate a hop explicitly (e.g. `"Chain
   confirmed. Severity 4."` with no node references at all), that hop is invisible to the
   `EdgeIntegrityWarnings` check either way — not because it's known-clean, but because there's
   nothing in the Reporter's text to check. This is a real limitation, not a bug: the alternative
   (falling back to Blue's confirmed hops when the Reporter is vague) was considered and not
   built, since it would blur exactly the reported/abandoned line case 5 required drawing clearly.
3. **Relation-word correctness is not checked.** If a hop names a real, correctly-directed edge
   but states the wrong relation (e.g. asserts `can-access` where the real edge is `used-by`),
   neither check catches it — only node-pair direction and node identity are verified. Whether
   this is worth adding, and how to weigh it against false positives from paraphrasing, is an
   open question rather than a decided scope cut.
4. **No structured field yet — text-block only.** `Report.Summary` carries both warning blocks as
   text, matching how the disclaimer already travels. SEC-40's read API / SEC-42's UI don't get
   structured fields to render the two categories distinctly. Whether that's worth a schema change
   (and the migration it implies) is a product call, not made here.
5. **Case 3's own root cause — non-determinism — has no mitigation beyond detection.** The
   mechanical check catches the wrong answer after the fact; it doesn't reduce how often a model
   gives one. Model choice, tool-based graph access instead of full-context stuffing, or
   temperature/sampling settings are all real levers, discussed but not pursued as part of this
   ticket — see the session's discussion on why none of them would have eliminated the need for
   this check even if adopted.

---

## 7. How to verify this yourself

```bash
cd sentinelai-backend
dotnet test tests/SentinelAI.Application.Tests --filter "FullyQualifiedName~EdgeAssertionValidatorTests|FullyQualifiedName~EdgeIntegrityDebateEngineTests"
```

Should show 30 passing (21 `EdgeAssertionValidatorTests` + 9 `EdgeIntegrityDebateEngineTests`).
Notably:

- `The_live_regression_is_caught_the_reversed_assumes_edge_and_nothing_else` (case 1),
  `The_second_live_regression_is_caught_the_fabricated_transitive_edge` (case 3), and
  `The_third_live_regression_is_caught_two_reversed_used_by_edges` (case 4) — three of the five
  live cases reproduced as standalone validator tests.
- `A_pairing_blue_invents_and_the_reporter_repeats_is_caught_via_the_reporter_turn` (case 2) and
  `An_abandoned_fabricated_path_does_not_cap_a_genuinely_clean_reported_chain` (case 5) — the two
  cases that specifically require decorator-level, multi-turn checking, in
  `EdgeIntegrityDebateEngineTests`.
- `Two_node_references_separated_by_a_comma_not_an_arrow_are_not_a_hop` — the comma-list
  false-positive fix found while reproducing case 5.

For the full `Application.Tests` suite (176 tests, includes everything above plus every other
Application-layer test unrelated to SEC-50):

```bash
dotnet test tests/SentinelAI.Application.Tests
```

Once `Integration.Tests` is unblocked:

```bash
dotnet test tests/SentinelAI.Integration.Tests --filter "FullyQualifiedName~ChainOutcomeWriter"
dotnet test SentinelAI.slnx
```

# Live-model findings

## What broke when real models replaced the stubs

**Scope:** observations from running the SEC-02 debate against NVIDIA NIM.
**Models exercised:** `nvidia/nemotron-3-super-120b-a12b`, `nvidia/nemotron-3-ultra-550b-a55b`
**Status:** three defects fixed, one open (§5).

---

## 0. Why this document exists

Every defect below passed the unit suite. All 32 tests are green against the `Scripted`
provider, and every one of these failures still reached a live run. That is the finding
that generalises: **an offline suite proves the orchestration, not the prompting.** The
scripted client returns exactly what the parser expects, so it can never catch a parser
that is too strict, a token budget that is too small, or an instruction a model reads
differently from its author.

Both categories of test are needed. Neither substitutes for the other.

---

## 1. The scripted client matched nothing (fixed)

**Symptom.** Every agent returned the same fallback string. Red, Blue and Reporter were
indistinguishable.

**Cause.** `ScriptedChatClient` inferred the role by sniffing the system message for the
agent's name. `ChatClientAgent` does not send instructions as a `ChatRole.System` message —
it passes them via `ChatOptions.Instructions`. The sniff matched nothing, silently, and
fell through to the default branch.

**Fix.** The role is passed to the client explicitly rather than inferred.

**Why it escaped the suite.** The tests asserted the debate's *shape* — three turns, right
order, shared state — and that shape is identical whether or not the agents say anything
role-appropriate. Regression tests now assert each role answers in character.

---

## 2. The token budget paid for thinking (fixed)

**Symptom.** Blue emitted ~500 words of raw scratchpad — *"We need to validate each hop…
Thus we have one hop unresolved… We need to decide format…"* — and stopped mid-sentence at
`"I think we"`. The Reporter's audit ended mid-word: `"attacker uploads malicious S"`.

**Cause.** These models narrate their reasoning as ordinary output. `MaxOutputTokens = 900`
was consumed by the preamble before either agent reached its answer, so Blue's verdict token
was never written.

**Fix.** `MaxOutputTokens` raised to 4000, plus `BlueTeamExecutor.StripReasoning` which
drops `<think>…</think>` blocks and, when a verdict token is present, discards everything
above the hop lines that precede it.

**Rule of thumb.** Budget for the reasoning *and* the answer. A cap sized for the answer
alone truncates before the answer starts.

---

## 3. An unparseable verdict was reported as success (fixed)

The most serious of the four, because it published a wrong result rather than an obvious
failure.

**Symptom.** A run whose final outcome block read:

```
converged         : True
weakest join      : Unresolved
```

**Cause.** `ReadVerdict` ended with `return (Converged: true, Readable: false)` — a failed
parse defaulted to converged. Blue's truncated round-2 response contained no verdict token
and none of the natural-language fallbacks, so it took that branch. `converged: True` was
reporting *"the parser gave up"*, not *"the chain held"*.

The confidence downgrade did fire — the run was correctly flagged `Unresolved` — so the
safety net worked. Only the headline lied.

**Fix.** Three parts:

1. `DebateTurn.VerdictReadable` carries the parse result as its own fact.
2. The fallback returns `Converged: false`. Routing no longer depends on it, because the
   Blue→Reporter edge now also fires on `!VerdictReadable` — a model that failed to answer
   is not re-asked until the turn-cap expires.
3. `DraftAudit.Outcome` replaces the raw boolean, checked most-doubtful first, so
   `VerdictUnreadable` can never be rendered as a convergence.

**Principle.** *Unknown* is a third state. Collapsing it into either *true* or *false*
produces a confident answer that no evidence supports.

---

## 4. Two console writers, no lock (fixed)

**Symptom.**

```
⠋ Blue waiting for model... 0s    N1 -> deserialization gadget chain -> lock file pins
```

**Cause.** `SpinnerChatClient` painted `\r…` from a background task while `Program.cs`
printed turns from the workflow event stream. Neither cleared the other.

**Fix.** `ConsoleOut` owns stdout behind a single lock. Any normal line erases a live
spinner before writing.

---

## 5. OPEN — Blue treats *unconfirmable* as *refuted*

**This one violates AID-01 §3.3 and is not yet fixed.**

**Symptom.** Three consecutive rounds, all identical:

```
round 1   N2→N3: UNRESOLVED  →  VERDICT: CHAIN_BROKEN
round 2   N2→N3: UNRESOLVED  →  VERDICT: CHAIN_BROKEN
round 3   N2→N3: UNRESOLVED  →  VERDICT: CHAIN_BROKEN
```

Round 3 in full: *confirmed, **UNRESOLVED**, confirmed, confirmed* → `CHAIN_BROKEN`.
Nothing was refuted. One hop could not be confirmed, and Blue killed the chain for it.

**What the design requires** (AID-01 §3.3):

> An `unresolved` edge … **does not kill the chain silently**. The Red agent may still
> assert the chain, and the Reporter surfaces it as a "potential chain, unverified join"
> for human confirmation — never as a confirmed verdict.

**Cause.** Blue's instructions say *"Breaking a single link breaks the whole chain"* and
*"Mark any hop you cannot confirm with the word UNRESOLVED"*, then demand `CHAIN_HOLDS` or
`CHAIN_BROKEN` — with nothing stating that UNRESOLVED is not BROKEN. The model draws the
only inference available to it.

**Cost.** Every live run burns the full turn-cap. The 550B run spent six debate calls and
134 seconds to produce an audit that two calls would have produced identically.

**Fix (proposed).** State in Blue's instructions that only a hop *contradicted by the
configuration* breaks the chain, and that unconfirmable hops are marked UNRESOLVED while the
chain still holds. `Converged` then means "no link refuted"; the confidence tier already
carries the unresolved-ness independently, so no new state is needed.

---

## 6. Latency

Measured, sequential, non-streaming.

| Model | Total | Per-call range | Note |
|---|---|---|---|
| `nemotron-3-super-120b-a12b` | 99.4 s (6 calls) | 6.2 – 32.4 s | steadier |
| `nemotron-3-ultra-550b-a55b` | 133.7 s (7 calls) | 4.4 – 55.3 s | Blue: 9.0 s then 55.3 s for near-identical output |

Three contributors, in order of cost:

1. **The turn-cap burn from §5.** Fixing it roughly halves wall-clock.
2. **No streaming.** `GetResponseAsync` blocks until the full response lands, so nothing
   prints until an agent finishes — a 30-second silence reads as a hang. This is what makes
   the run *look* stuck; it is not.
3. **The Orchestrator's own model call** (6–12 s) before Red starts.

Nothing here is a deadlock. Summed call times account for essentially the whole elapsed
figure in both runs.

---

## 7. Known cosmetic issue

`Wrap()` in the demo splits on spaces only, so newlines the model emitted survive into the
middle of a wrapped line:

```
N1 → N2: VALIDATED — lock file pins 3.2.1, code imports InvokerTransformer
N2
    → N3: UNRESOLVED — INFERRED image-name join
```

Presentation only; the stored turn content is intact.

---

## 8. What the agents are actually good at

Assessed from the 550B transcript, so the credit is as evidence-based as the criticism.

**Strong.** Red builds well-formed four-hop chains using the real node IDs, correctly tags
the convention-dependent join `INFERRED`, and never invents an edge outside the supplied
graph. Blue validates hop by hop and isolates exactly the one join that cannot be confirmed
— its discrimination is right even where its conclusion is wrong. The Reporter ranks by
exploitability, separates confirmed findings from the potential chain, and applies the
draft-not-verdict framing without being reminded.

**Overstated.** The Reporter's `[F1, F2, N1→N2 confirmed]` markers look like citations but
are echoes of the prompt, not retrieved knowledge chunks. AID-01 §7 requires every assertion
to cite its retrieved chunk from Qdrant. Until SEC-06→09 land, the agents are grounded in
*the prompt*, which is a materially weaker claim. Do not describe this as grounding coverage
in a review.

**Not yet demonstrated.** Red asserts the same chain every round. Partly §5, but partly
because the stub graph contains exactly one path — with one path there is nothing else to
assert, so the debate cannot yet be adversarial in the way the design intends. A real
multi-path graph is what makes this testable.

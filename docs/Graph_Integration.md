# Integrating the resource graph

## Handoff notes for SEC-03 / SEC-08

**Audience:** whoever builds the canonical contracts and the resource graph.
**Short answer:** the debate is ready for a real graph. The work is a serializer, not a
redesign.

---

## 1. Where the graph enters today

One seam, and it is stringly-typed:

```csharp
// OrchestratorExecutor.cs
public sealed record ScanBrief(string ScanJobId, string Context);
```

`ScanBrief.Stub()` supplies a hand-written prose graph, which the Orchestrator writes into
shared state as `DebateState.ResourceGraph` (a `string`). Red and Blue interpolate it
straight into their prompts.

```
ScanBrief.Context ─> DebateState.ResourceGraph ─> Red prompt
                                               └─> Blue prompt
```

The stub graph — five nodes, four edges, one deliberately `INFERRED` join — models the
AID-01 fixture, so the agents already reason over the exact shape a real graph will have.

---

## 2. What changes, and what does not

**Unchanged.** The workflow graph, shared session state, checkpointing and resume, the
turn-cap, the provider abstraction, the four per-agent credentials, every acceptance test.
None of it knows the graph is a string.

**Changes.** One narrow layer:

1. `ScanBrief` gains typed fields — findings, nodes, edges — from the SEC-03 contracts.
2. A renderer turns the typed graph into the prompt block that `ResourceGraph` holds today.
3. `ScanBrief.Stub()` becomes a fixture built from typed objects rather than a literal.

That is the whole integration. The debate does not need to know the difference.

---

## 3. Four things to get right

### 3.1 Align the node IDs first — they already drift

The stub emits:

```
N4=iam-role:api-task-role
```

SEC-03 specifies canonical `type:identifier` with `iam_role:name` — **underscore**, not
hyphen. That single character is exactly the failure SEC-03's island guard exists to catch:

> If two extractors disagree on IDs, the graph silently splits into disconnected per-layer
> islands.

Fix it while one file emits node IDs. Once the graph builder, the normalizer and the
fixture all emit them, it is a three-repo change plus a debugging session.

**Recommendation:** centralise the ID helper in the shared contracts, as SEC-03 step 2
requires, and have this repo consume it rather than hand-writing IDs.

### 3.2 Keep typed objects out of checkpointed state

`DebateState` is serialised to JSON after every superstep. Put the typed graph in it and any
schema change breaks resume from existing checkpoints — an unforced compatibility burden.

**Recommendation:** the typed graph travels in `ScanBrief`; `DebateState.ResourceGraph`
keeps the rendered string. State stays a stable, human-readable projection.

### 3.3 Give Blue the graph as independent ground truth

Today Red and Blue receive the same text, and Blue validates against Red's *restatement* of
the chain. That means Blue is largely checking internal consistency, not checking Red
against reality — which is weaker than the false-positive reduction the design claims.

**Recommendation:** once a real graph exists, hand Blue the graph directly and Red's claim
separately, so a hop Red invented or misquoted fails against the source rather than being
silently accepted.

### 3.4 Generate bounded candidate chains before the debate

A real repository's graph will not fit in a prompt. AID-01 §3.2 already answers this:

> Candidate chains are capped at **3–4 hops**, seeded from the highest-severity "hot"
> findings … The Red agent reasons within deterministically-generated candidates (real
> edges only) rather than over the free graph.

**Built — SEC-20.** `ExploitChainTraverser` (Application) generates them; `CandidateChainWriter`
persists them as `chains`/`chain_hops` and returns the typed `CandidateChain` list for the
handoff. It sits on the graph side of the seam, as this section asked. The bounds, the ATT&CK
tactic ordering that constrains direction, and the ranking are documented in
`Data_Contracts.md` §6.

What remains for the debate side: `ScanBrief` still carries a rendered string, and
`ScanBriefRenderer` still renders nodes with an explicit "no edges were extracted" line. Feeding
it candidate chains instead of a bare node list is the next step, and it is the natural moment
to also do §3.3 — hand Blue the graph as ground truth separately from Red's claim.

---

## 4. Multi-path graphs make the debate testable

The stub graph has exactly **one** path, so Red asserts the same chain every round — there
is nothing else to assert. The adversarial dynamic the design depends on cannot be observed
until Red has a genuine choice between candidates.

A fixture with two or three plausible chains, one of which Blue can actually refute, is the
smallest thing that would demonstrate the thesis rather than merely exercise the plumbing.

---

## 5. Suggested order

1. Centralise the canonical node-ID helper (SEC-03) and align this repo's stub to it.
2. Land typed `Finding` / `Node` / `Edge` contracts.
3. Add the renderer, keep `DebateState.ResourceGraph` a string.
4. Rebuild `ScanBrief.Stub()` from typed fixture objects — the acceptance tests should stay
   green untouched, which is the proof the seam held.
5. Add candidate-chain generation, then split Blue's ground truth from Red's claim.

Steps 1–4 are mechanical. Step 5 is where the design questions live.

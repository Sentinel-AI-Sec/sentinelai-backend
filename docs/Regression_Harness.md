# Full-flow regression harness (SEC-49)

**Where:** `tests/SentinelAI.Integration.Tests/Regression/`
**Runs:** in the normal suite, and again as its own CI step so a failure is legible in the log.

---

## What it is

One repeatable run of the reference fixture through the whole product — from a real multipart
upload to `POST /v1/scans`, out through `GET /v1/reports/{id}` — with a record of what every
stage produced.

```
Ingest → Normalize → Graph → Chain → Retrieval → Debate → Report → ReadBack
```

Each stage is checked for whether it produced what the *next* one needs. The run stops at the
first stage that did not, and the failure message carries the whole table:

```
SEC-49 full-flow run for scan job 01a019ee-d3e4-770c-881b-473585ab351d
  BROKEN AT: Graph

  [ok  ] Ingest    202 Accepted, 3457 bytes stored, job 01a019ee-…
  [ok  ] Normalize 4 finding(s): Code=1, Dep=1, Infra=2
  [FAIL] Graph     8 node(s) and no edges — the graph is islands
  not reached: Chain, Retrieval, Debate, Report, ReadBack
```

That table is the deliverable, not a nicety. SEC-49's second acceptance criterion is that a
regression *pinpoints its stage*, and a pinpoint that stays on the machine where the run
happened has not pinpointed anything.

## Why it goes through HTTP

Every other suite in this repository composes the stage classes directly. That is the right tool
for testing a stage and the wrong one here.

Five sprints of audits found every blocking defect in a **seam**, never inside a component:

| Finding | The seam |
|---|---|
| 26-A | graph → debate (Red never saw real edges) |
| 42-A | backend → UI (fields rendered but never written) |
| 44-A / 44-B | deployed API → deployed UI (no CORS, never connected) |
| D1 | Action → ingest endpoint (nothing ever posted a form) |

Composing the services by hand rebuilds the seams out of the same assumptions that would be
wrong. Posting a real tarball and reading the result back out of the read API does not.

The harness found one on its first run. `ChainHopView.NodeKey` was read from the hop's own edge,
which the seed hop does not have — so every chain the read API served began one hop late, and the
dashboard drew the flagship chain without its dependency layer. The graph stage's own response
carried the full five-node path the whole time. Two halves, each individually green. The fix is in
`ChainView.HopsOf`.

## What it asserts

| Criterion | Test |
|---|---|
| The three-layer chain reconstructs | `The_three_layer_flagship_chain_reconstructs` |
| Per-layer finding counts, exactly | `Every_layer_contributes_the_findings_the_fixture_implies` |
| All three retrieval modes fire | `All_three_retrieval_modes_fire_over_the_fixture` |
| Edges oriented in attack direction | `Every_persisted_edge_is_oriented_in_attack_direction` |
| Expected cited path present | `The_expected_cited_path_is_present_in_what_the_read_api_serves` |
| A broken stage names itself | `A_broken_stage_names_itself_and_the_stages_after_it_stay_silent` |

Counts are exact rather than "at least one". A harness that asserts non-emptiness passes on a run
that lost two thirds of its findings — which is not hypothetical here: routing only `osv.json`
when the runner writes `osv.sarif` dropped an entire scanner's output, and the scan looked clean.

## The golden bundle, and the copy problem

`GoldenBundle.cs` holds the fixture's golden path as constants and builds a real `.tar.gz` from
them. The fixtures are a sibling repository, not a submodule, so a backend-only checkout — which
is what CI does — has none of them. A harness that skipped there would be a regression harness
that never runs on the change that broke something.

A committed copy can drift from what it copies, and has: for one sprint `FlagshipChainTests`
asserted the flagship chain over a Dockerfile carrying `LABEL org.sentinelai.image` that the real
fixture did not have. Green the whole time, broken the whole time.

`FixtureParityTests` closes that. When `sentinelai-fixtures` is checked out beside this
repository it compares every copied file against the original and names the first differing line;
when it is not, it skips with a stated reason and the harness still runs. **Measured everywhere,
verified wherever verification is possible.**

To get the parity checks running locally:

```
workspace/
  sentinelai-backend/     ← you are here
  sentinelai-fixtures/    ← clone beside it
```

## Retrieval modes

`RetrievalMode.Semantic` versus `RetrievalMode.Hybrid` is decided by the **embedder**, not by the
finding: a model with no lexical half can never produce a sparse vector, so hybrid never fires in
that deployment however many findings are scanned. Proving "all three modes fire" therefore means
concatenating results from more than one configuration — `RetrievalEvaluation`'s own remarks say
so, and `FullFlowHarness.MeasureRetrievalAsync` does exactly that: it runs the real
`KnowledgeRetrievalService` over the findings this scan produced, once with a dense-only embedder
and once with a hybrid one, and evaluates the union.

The corpus behind it (`RegressionCorpus`) is deterministic and deliberately uneven: CWE-502 and
CWE-284 have weakness definitions, so those findings are answered by the exact arm; CVE-2024-21907
and CWE-778 are absent, so theirs fall through to the meaning-based arms. A corpus that answered
everything exactly would report 100% grounding coverage while leaving two thirds of SEC-22
unmeasured.

**What this does not measure** is the live corpus. That is `LiveCorpusSmokeTests`, which builds
its own container and skips when none is reachable.

## Cost and determinism

Scripted model provider, in-memory SQLite, no network, no keys, no tokens spent. The run takes
about five seconds. That is the only reason it can run on every push, which is the only way a
regression harness earns its name.

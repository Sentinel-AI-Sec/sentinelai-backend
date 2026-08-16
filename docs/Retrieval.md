# Retrieval (SEC-22)

**Audience:** whoever builds the offense/defense split (SEC-23), deprecated filtering (SEC-24),
or grounding evaluation (SEC-25).
**Short answer:** one flow, three modes, two rules that are enforced by types rather than by
convention.

---

## 1. The decision tree

```
finding arrives (as SEC-21's FindingQuery)
   │
   ├─ clean CVE? ─── exact filter: cve_id + source=NVD ─── hit ──► done (ExactFilter)
   │                                                    └─ miss ─► record it, fall through
   │
   ├─ clean CWE? ─── exact filter: cwe_id + source=CWE ─── hit ──► done (ExactFilter)
   │
   └─ embed the NL query ──► filtered search ──► Hybrid if the embedder has a lexical half,
                                                 Semantic if it does not
```

`KnowledgeRetrievalService` is that tree, and it is pure — Qdrant sits behind `IKnowledgeSearch`
and the model behind `IQueryEmbedder`, so every branch is unit-tested against an in-memory
corpus rather than only against a live cluster.

**CVE then CWE, separately.** They are not interchangeable: the CVE is the specific
vulnerability, the CWE is its weakness class. Falling straight from a CVE miss to semantic
search would throw away a weakness definition that is sitting right there.

---

## 2. Two rules the type system enforces

### `ExactLookup` has no public constructor

Because the `source` condition is not optional. `PIPELINE_A_CONTEXT.md` §4 measured what
omitting it costs:

```
cwe_id=CWE-502 alone          → 825 points, top 3 are NVD CVEs
cwe_id=CWE-502 + source=CWE   → 2 points, the actual definition
```

The 825 are CVEs merely *tagged* with that weakness. The document calls this "the single most
dangerous bug shape in this system", because it returns something confident and irrelevant while
grounding coverage reports 100%. A convention would not have caught it; `ExactLookup.ForCve` and
`ForCwe` being the only ways in does.

### `SemanticQuery` refuses to be unfiltered

With 26,283 NVD chunks against 172 OWASP chunks, an unfiltered semantic query returns CVEs
whatever it was asked. That is a **ranking** problem, not an ingest gap — the guidance is
present, it is outnumbered 150 to 1. Either a `source` or a `content_type` filter satisfies the
rule; both cut the CVE bulk out of the candidate set, which is the property that matters.

`RetrievalIntent` is §4's table in code, and every row carries a filter — there is no
"unfiltered" intent to reach for:

| Intent | Collection | Filter |
|---|---|---|
| `HowAnAttackerWould` | offense | `source in (ATTACK, CAPEC)` |
| `HowToFix` | defense | `content_type=mitigation` |
| `HowToDetect` | defense | `content_type=detection` |
| `WhatTheStandardSays` | defense | `source=OWASP` |

`HowToFix` filters on `content_type`, not `source`, because CWE *and* CAPEC both carry
mitigations — picking either source alone would drop half the remediation guidance in the corpus.

---

## 3. Misses are reported, never hidden

`PIPELINE_A_CONTEXT.md` §7: CVE coverage is partial by design. When a finding's CVE is outside
the corpus's NVD slice, retrieval falls back to the weakness class — and says so, via
`RetrievalResult.Misses`.

A silent fallback reads downstream as a direct hit on the specific CVE, which is a claim the
audit cannot support. `RetrievalMiss` has three shapes: the CVE was not in the corpus, the
finding had no clean identifier at all, or nothing came back and the finding is ungrounded.

`RetrievalResult.Mode` records which arm answered, per finding. SEC-25 turns that into an
asserted metric; the service already logs coverage and per-mode counts.

---

## 4. What SEC-22 does not do

- **Which agent asks** — SEC-23. `RetrievalIntent` is keyed on the question, not the agent, so
  the Reporter can ask a defensive question without pretending to be Blue.
- **Deprecated filtering** — SEC-24. `QdrantOptions.PrefetchMultiplier` already over-fetches 4×
  per vector, which is the headroom that story needs to drop entries and still return `k`.
- **Grounding coverage as an assertion** — SEC-25.
- **Corpus-manifest parity** — SEC-48. `QdrantKnowledgeSearch.VerifyCompatibleAsync` does the
  cheap half (collection exists, dense width matches); comparing the embedder's pinned revision
  against the manifest needs Pipeline A to publish one.

---

## 5. The adapter

`QdrantKnowledgeSearch` is a translation layer and nothing else. Its three call shapes mirror
`sentinelai_knowledge/validate.py`, which is the implementation already validated against the
live corpus:

| Mode | Call |
|---|---|
| Exact | `Scroll` with a payload filter. No vector. Score is 0 — a filter matches, it does not rank |
| Semantic | `Query` with `using: "dense"` |
| Hybrid | `Query` with two prefetches and `Fusion.Rrf` |

**The filter goes on each prefetch, not on the outer fusion query.** Fusion combines whatever the
prefetches returned; filtering afterwards would rank the CVE bulk first and *then* discard it,
returning fewer than `k` — or none — while looking like it worked.

Its tests are gated behind `SENTINELAI_QDRANT` (see `Configuration.md` §6.3) because CI has no
corpus. They report as **skipped**, not passed.

---

## 6. The embedder

Query-time vectors come from a **service**, not from a model loaded in this process:
`sentinelai-knowledge/service/` wraps the same `embedder.py` the ingest used and serves it over
HTTP. `HttpQueryEmbedder` is the adapter. See `Configuration.md` §6.2 for deploying it.

**One definition of the model, not two.** The same-model invariant holds because the service
imports Pipeline A's own embedder and reads `config/ingest.yaml` — not because two
implementations were kept in step. That was the deciding argument against running BGE-M3
in-process: an ONNX port would have re-implemented tokenisation and pooling in C#, and both are
places where a mistake produces a plausible wrong answer rather than an error.

**It is also the only way to keep sparse.** Commercial embedding APIs return one dense vector.
Our own service returns BGE-M3's lexical half too, so mode 3 actually fires instead of being
permanently unavailable.

### What the adapter refuses to do

It never falls back. A failed call throws — the same stance `get_embedder` takes in Python by
calling `sys.exit` rather than coping. An embedder that quietly returned something on failure
would ground the debate in vectors from nowhere and report success.

A vector of the wrong width is refused rather than queried with, and null-or-empty sparse both
become no sparse vector: an empty sparse prefetch matches nothing, so a hybrid search would find
only the dense half while reporting that it fused two.

### Cold starts and parity

`KnowledgeReadinessService` runs in the background at startup — not as a blocking check like
`ProviderReadiness`, because a free HuggingFace Space that has slept takes minutes to wake and
blocking the host on that would take down auth, ingest and the graph stage over an optional
dependency.

The two failures mean different things and are treated differently:

| | |
|---|---|
| **Unreachable** | Warned, host keeps running. The exact-filter arm needs no embedder. |
| **Reachable, wrong model** | Fatal. Every semantic result would be confident and meaningless, and nothing downstream can detect it. |

**A matching dimension is not evidence of a matching model** — plenty of models are 1024-wide.
That is what `/parity` is for. Set `Knowledge:Embedder:ExpectedNorms` from the ingest's
`parity_check()` and startup compares them; leave it empty and only the width is checked, which
the log says explicitly rather than reporting a pass that sounds like more than it is.

The tolerance exists because index time ran on GPU and query time runs on CPU, so the same model
does not produce bit-identical floats. It produces very close ones. A different model moves those
numbers far more than the tolerance absorbs.

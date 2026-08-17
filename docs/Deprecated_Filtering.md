# DEPRECATED / low-quality filtering (SEC-24)

**Audience:** whoever reviews this story, or later wonders why a filter that never removes
anything is in the hot path of every retrieval.
**Short answer:** because the failure it catches is silent, and because the corpus that makes it
unnecessary is built by a different repository on a different schedule.

> Related: [`Retrieval.md`](Retrieval.md) is the decision tree this hangs off (SEC-22/SEC-23).
> [`Knowledge_Setup.md`](Knowledge_Setup.md) is how to get a corpus to run it against.

---

## 1. What the story is actually defending against

A retired CAPEC pattern or ATT&CK technique keeps its entry but loses its body — MITRE leaves two
lines of stub text behind. Short text sits near the centre of the vector space, so it scores well
against **almost any** query. The result is not an error and not an empty list: it is confident
junk at rank one, cited in the audit, with grounding coverage reporting 100%.

That is the same failure shape as a missing `source` condition on an exact lookup
(`PIPELINE_A_CONTEXT.md` §4 calls that "the single most dangerous bug shape in this system"), and
it is worth handling the same way — by making it impossible to skip rather than by remembering.

**Pipeline A already handles it at ingest.** `PIPELINE_A_CONTEXT.md` §7:

> Deprecated entries are filtered at ingest, not at retrieval. CAPEC uses `x_capec_status` (not
> ATT&CK's `revoked`); CAPEC `Draft` means published-and-usable and is kept — 723 of them. **SEC-24
> keeps the over-fetch-and-filter guard as belt and braces.**

So this story is a second line of defence, deliberately. It exists because the corpus is data
produced by another repo on another schedule: the backend can be pointed at a cluster built by an
older loader, or by something that is not Pipeline A at all, and nothing else in the system would
notice.

---

## 2. The corpus, measured

Scrolling both collections at `corpus_version 2026-08-10-1143`, reading every point's `status`,
`title` and `text`:

| | `offense` | `defense` |
|---|---:|---:|
| Points | 28,950 | 31,179 |
| `status` = Deprecated or Obsolete | **0** | **0** |
| Title beginning `DEPRECATED` | **0** | **0** |
| `text` shorter than 40 characters | **0** | **0** |
| Shortest `text` seen | **exactly 40** | **exactly 40** |

The guard is a no-op on this corpus. That is the expected result, and
`LiveCorpusQualityTests` asserts it rather than assuming it — a filter that never fires and a
filter that is broken look identical until something checks.

The shortest chunk being *exactly* 40 characters is not a coincidence: it is
`preprocess.MIN_USEFUL_CHARS`, the ingest's own cutoff, showing through.

### The status values that are actually in there

| | `offense` | `defense` |
|---|---:|---:|
| (no status field) | 26,980 | 29,094 |
| Draft | 1,155 | 1,098 |
| Incomplete | 486 | 788 |
| Stable | 325 | 197 |
| Usable | 4 | 2 |

Only CWE and CAPEC carry `status`. ATT&CK, NVD and OWASP points have no such key.

---

## 3. Three decisions, and what each one would cost if made the other way

### 3.1 The filter is client-side because Qdrant refuses the alternative

The obvious implementation is another condition on the query, next to `source` and `content_type`.
It does not work. `status` is a payload field but **not an indexed one** (`PIPELINE_A_CONTEXT.md`
§3 lists the twelve that are), and this cluster rejects a filter on an unindexed key rather than
falling back to a scan:

```bash
curl.exe -s -H "api-key: $KEY" -X POST "$URL:6333/collections/offense/points/count" -H "Content-Type: application/json" -d '{"exact":true,"filter":{"must":[{"key":"status","match":{"value":"Deprecated"}}]}}'
```

**HTTP 400**, for every value, on both collections. So the condition cannot ride along on the
query; it has to be applied to results after they come back — which is exactly what
"over-fetch-and-filter" means and why the story is worded that way.

### 3.2 Over-fetch is its own multiplier, not the prefetch one

`QdrantOptions.PrefetchMultiplier` (4×) looks like it would serve. It does not: it widens the two
*inputs* to Reciprocal Rank Fusion, and fusion still emits exactly `limit` points. After it runs
there are `k`, and dropping any leaves fewer than `k`. The dense-only path settles it — no
prefetch at all, `limit` straight to Qdrant.

So `ChunkQuality.OverFetch` raises the **outer** limit, and the two multiply:

```
10 wanted  ->  20 requested  ->  80 prefetched per vector (hybrid)
```

2×, not 4×, because the expected drop rate is zero — this is headroom against a stale corpus, not
a routine cost, and a factor of four would double Qdrant's work to insure against something that
currently never happens.

**One real side effect, stated rather than glossed.** Because the two multiply, the hybrid
prefetch went from 40 per vector to 80. Taking the top 10 of a filtered top 20 returns exactly
the top 10 when nothing is dropped — that part is free — but a wider prefetch gives RRF a larger
candidate set, so a chunk ranked 50th by dense and 3rd by sparse can now reach the fused list
where before it could not. Rankings on a clean corpus may therefore shift slightly. The direction
is toward what fusion is for; the honest statement is that it is a change, not a no-op.

*(Earlier drafts of `Retrieval.md` §4 and `QdrantOptions` both claimed the prefetch multiplier was
this headroom. Both are corrected.)*

### 3.3 Three signals, because each source marks retirement differently

| Signal | Covers | Why it alone is not enough |
|---|---|---|
| `status` in (`Deprecated`, `Obsolete`) | CWE, CAPEC | **ATT&CK has no `status` in the payload at all.** Its loader reads `revoked`/`x_mitre_deprecated` and does not carry them through. |
| Title begins `DEPRECATED` | all sources | Only fires if MITRE renamed the entry, which is convention rather than schema. |
| `text` under 40 characters | all sources | Catches stubs whatever marked them, but a retired entry with a full body slips past. |

The ATT&CK row is the one that matters: check `status` alone and half of what the story's title
names — "DEPRECATED **CAPEC/ATT&CK** entries" — is silently unimplemented.

Each rule is **copied from Pipeline A, not invented here**: `DEAD_STATUS` from `loaders/capec.py`
and `loaders/cwe.py`, the title prefix from `capec.py`'s `is_live`, the length from
`preprocess.py`'s `MIN_USEFUL_CHARS`. A guard that disagreed with the ingest it backs up would be
worse than no guard — it would either pass what the ingest drops or drop what the ingest
deliberately keeps, and both read as a corpus problem from this side.

---

## 4. The rule that is *not* applied, and why it is the expensive mistake

The tempting simplification is an allow-list: keep `Stable`, drop the rest. It is catastrophic
here, and the corpus says by how much.

```
CWE chunks in offense:   Draft 432, Incomplete 486, Stable 26
CAPEC chunks in offense: Draft 723, Stable 299, Usable 4
```

**Twenty-six of 944 CWE chunks are `Stable`.** "Only stable" throws away 97% of the weakness
catalogue — the catalogue every code and infra finding resolves into through the rule-mapping
table (SEC-12/SEC-15), and the one thing that lets a finding with no CVE reach a technique at all.

- `Draft` in CAPEC means *published and usable, still being refined*. It is the majority of the
  catalogue; `capec.py` says so in its module docstring and §7 counts the same 723.
- `Incomplete` in CWE means the entry is still being fleshed out, not withdrawn.

Over-filtering this corpus costs more than under-filtering it, and it fails in the same invisible
way — as a coverage number that quietly drops.

The same reasoning applies to the title rule being a **prefix** match rather than a substring:
CWE-477 "Use of Obsolete Function" and CWE-1104 "Use of Unmaintained Third Party Components" are
live weaknesses whose subject *is* deprecation. A substring match on "obsolete" would delete
exactly the guidance a finding about a stale dependency needs.

---

## 5. Where it sits in the tree

```
finding arrives
   │
   ├─ exact CVE ──► ChunkQuality.Apply(chunks)          no over-fetch: a filter matches, not ranks
   │                  └─ all dropped? ──► fall through, and record NothingUsable
   │
   ├─ exact CWE ──► ChunkQuality.Apply(chunks)
   │
   └─ semantic ───► ask for OverFetch(k) = 2k
                      └─ ChunkQuality.Apply(chunks, k)  ──► exactly k survive
```

Both arms, so there is no path from the corpus to the debate that skips it. The policy lives in
`ChunkQuality` (pure, Application layer); `KnowledgeRetrievalService` only decides *where* it
applies, which is everywhere.

**An exact hit that is entirely deprecated falls through rather than being returned.** Returning
it would be the worst outcome available — a deterministic, top-ranked, confidently cited chunk
that the source itself has withdrawn. Falling through means the CWE arm, and then meaning, still
get their turn.

### Misses stay honest

`RetrievalMiss.NothingUsable` is deliberately not folded into `Ungrounded`:

| | Means | Fix |
|---|---|---|
| `Ungrounded` | the corpus was asked and had nothing | none — it is a real knowledge gap |
| `NothingUsable` | the corpus had something and it was retired or empty | re-run Pipeline A |

They are indistinguishable in a coverage number and have nothing in common. Every drop is also
logged at **warning** level, not debug: on a corpus Pipeline A built this never happens, so a
non-zero count is not routine housekeeping — it means the corpus in use was built by something
else, and every semantic result from it is suspect in a way nothing else reports.

---

## 6. The tests

| Filter | Count | Needs | Proves |
|---|---:|---|---|
| `~ChunkQualityTests` | 30 | nothing | The policy: what is dropped, what is kept, the over-fetch arithmetic |
| `~LowQualityFilteringTests` | 7 | nothing | The guard is reached on both arms, and `k` results still come back |
| `~LiveCorpusQualityTests` | 4 | **corpus** | The `status` field is really read, and the live corpus needs none of it |

The keep-cases carry as much weight as the drop-cases, for §4's reason.

Two are worth singling out:

- **`Asking_for_only_k_would_have_returned_almost_nothing`** — the counterfactual. Against a corpus
  whose top nine hits are retired, a request for 10 filters down to **1**; the over-fetched request
  returns a full **10**. That is the measurement that makes the multiplier necessary rather than
  decorative.
- **`The_adapter_reads_the_status_field_the_guard_depends_on`** — if Pipeline A ever renames
  `status`, every chunk arrives with a null one, the deprecation check silently passes everything,
  and nothing else in the suite notices. Same cross-repo string hazard `CorpusWire` exists to
  contain.

---

## 7. What SEC-24 does not do

- **Rank anything.** Qdrant decided the order; this only removes, preserving it. One authority per
  answer.
- **Judge relevance.** A live chunk that is a poor match for the finding is a retrieval problem
  (SEC-22's filters) or an evaluation one (SEC-25), not a quality one.
- **Fix the corpus.** It reports; re-ingesting is Pipeline A's job. The warning log and
  `NothingUsable` exist to make that call actionable rather than to work around it.

# Retrieval evaluation (SEC-25)

**Audience:** whoever needs to say, with evidence, that the audit's assertions are backed by
retrieved knowledge — and whoever later wonders why a story measured two numbers instead of one.
**Short answer:** because coverage and fire rates fail differently, and the failure coverage
cannot see is the dangerous one.

> Related: [`Retrieval.md`](Retrieval.md) is the decision tree being measured (SEC-22/SEC-23).
> [`Deprecated_Filtering.md`](Deprecated_Filtering.md) is the quality guard in front of it
> (SEC-24). [`Knowledge_Setup.md`](Knowledge_Setup.md) is how to get a corpus to run any of it.

---

## 1. Two numbers, because one of them lies on its own

**Grounding coverage** is the fraction of findings that came back with at least one chunk. It is
the audit's honesty bound: an assertion about an ungrounded finding has nothing behind it, so
coverage is the ceiling on how much of a report can legitimately be cited.

**Per-mode fire rates** are how many findings each arm of the decision tree answered.

The second exists because the first can report a perfect score on a broken system. Every finding
in a typical fixture carries a CWE, so the exact arm answers all of them:

```
grounding coverage 5/5 (100%) — exact 5, semantic 0, hybrid 0, ungrounded 0
```

That is a complete pass by coverage alone, and modes 2 and 3 have never run. The first
identifier-less infra finding in production is then the experiment. `Full_coverage_does_not_mean_every_mode_was_exercised`
is that scenario, pinned as a test.

So SEC-25 reports both, and `RetrievalEvaluation.Report()` names the modes that never fired
rather than leaving their zero to be noticed:

```
grounding coverage 5/5 (100%) — exact 5, semantic 0, hybrid 0, ungrounded 0;
0 fell back to the weakness class. Modes that never fired: semantic, hybrid
```

---

## 2. Measured on the live corpus

`LiveCorpusEvaluationTests`, five findings spread across dep / code / infra, against Pipeline A's
real 32,432 chunks with **no embedding service configured** — the configuration most machines and
most CI runs actually have:

| | |
|---|---|
| Grounding coverage (offense) | **5/5 — 100%** |
| Grounding coverage (defense) | **5/5 — 100%** |
| Modes that fired | exact only |
| Modes that never fired | semantic, hybrid |

Both halves of the corpus answer, so SEC-23's split holds on real knowledge and not just against
a fake. And the run is honest about being a one-mode run — which is the whole argument of this
story in a single line of output.

Turn on Level 3 of [`Knowledge_Setup.md`](Knowledge_Setup.md) and the other two modes become
reachable; `Perfect_coverage_without_an_embedder_still_reports_two_modes_as_never_fired` is
written so that it fails, informatively, on the day someone does that.

---

## 3. Decisions worth knowing about

### 3.1 Findings, not chunks

A finding that retrieved ten chunks and one that retrieved a single chunk are both grounded.
Averaging chunk counts would let a handful of rich results hide a finding with nothing behind it —
exactly the case the metric exists to surface. Coverage is a count of findings over findings.

### 3.2 An empty run scores 100%, not 0%

Every one of its zero findings is grounded. Scoring zero would make the cleanest possible scan —
no findings at all — trip a coverage threshold and read as a total retrieval failure.

### 3.3 Coverage is truncated, never rounded

199 grounded out of 200 is **99%**. Rounding to 100% would erase the one finding the audit cannot
support, which is the single number this metric exists to protect.

### 3.4 `None` is not a fourth mode

It is the ungrounded bucket. Counting it among the answering modes would make "all modes fired"
satisfiable by a run that grounded nothing at all.

### 3.5 "All three modes fire" is a claim about a *configuration*, not a corpus

Hybrid versus semantic is decided by the **embedder**, not by the finding: a deployment whose
model has no lexical half can never fire hybrid, however many findings it is given. So proving
all three requires measuring across more than one configuration, which is why
`RetrievalEvaluation.Of` takes *results* rather than running the retrieval itself — a test
concatenates a sparse-capable run with a dense-only one.

### 3.6 The weakness-class fallback is counted separately

Those findings are grounded — in the weakness class rather than the specific CVE, because the NVD
slice is partial by design (`PIPELINE_A_CONTEXT.md` §7). Coverage says 100% and is right. The
audit is still less specific than it looks, and only this number says so.

### 3.7 One definition of the number

`KnowledgeRetrievalService` logged coverage from the day SEC-22 landed, computing it inline. It
now logs *through* `RetrievalEvaluation`, so the value a test fails on and the value a log prints
cannot drift. It also logs at **warning** when a finding went unanswered, because that is a fact
about the report's trustworthiness rather than routine progress.

---

## 4. Using it

```csharp
var results    = await retriever.RetrieveAllAsync(findings, RetrievalIntent.HowAnAttackerWould);
var evaluation = RetrievalEvaluation.Of(results);

if (!evaluation.FullyGrounded)  logger.LogWarning("{Report}", evaluation.Report());
if (!evaluation.AllModesFired)  logger.LogWarning("{Modes}", evaluation.ModesThatDidNotFire);
```

| Member | Is |
|---|---|
| `Findings` / `Grounded` / `Ungrounded` | Counts of findings |
| `GroundingCoverage` | 0–1 fraction |
| `CoveragePercent` | Whole percent, truncated |
| `FullyGrounded` | Every finding retrieved something |
| `Count(mode)` | Findings answered by one arm |
| `AllModesFired` | All three answering modes fired at least once |
| `ModesThatDidNotFire` | The ones that did not — empty is healthy |
| `FellBackToWeaknessClass` | Grounded, but in the CWE rather than the CVE |
| `Report()` | The one-line summary above |

`RetrieveAllAsync` logs it for you; call `Of` directly when you want to assert on it or span
several runs.

---

## 5. The tests

| Filter | Count | Needs | Proves |
|---|---:|---|---|
| `~RetrievalEvaluationTests` | 11 | nothing | The metric: both halves, the arithmetic, the edge cases |
| `~LiveCorpusEvaluationTests` | 4 | **corpus** | The real numbers, on real knowledge, in the real configuration |

The two that carry the story:

- **`Full_coverage_does_not_mean_every_mode_was_exercised`** — 100% coverage *and* two modes
  never fired, in the same assertion. The reason the story measures two things.
- **`Perfect_coverage_without_an_embedder_still_reports_two_modes_as_never_fired`** — the same
  claim against the live corpus, so it is a fact about Pipeline A's knowledge and not about a fake.

---

## 6. What SEC-25 does not do

- **Judge relevance.** Coverage says a chunk came back, not that it was a good chunk. Whether the
  right knowledge was retrieved is SEC-22's filters (and, for retired entries, SEC-24's guard).
- **Gate the pipeline.** It reports; nothing fails a scan on a coverage threshold. A scan that
  grounds badly still produces a report — one whose citations are thinner, which is what the
  Reporter is meant to say out loud.
- **Measure the debate.** Whether an agent *used* the knowledge it was handed is SEC-26/SEC-27.

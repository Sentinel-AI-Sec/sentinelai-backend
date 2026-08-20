# Precision and recall vs SonarQube & Snyk (SEC-39)

**Scorer:** `src/SentinelAI.Application/Features/Benchmark/`
**Runner:** `tools/SentinelAI.Benchmark/` (`sentinelai-benchmark`)
**Tests:** `tests/SentinelAI.Application.Tests/Benchmark/` — 32, no corpus required
**Depends on:** SEC-38's ground-truth corpus (lives in `sentinelai-fixtures`)

---

## Running it

```bash
dotnet run --project tools/SentinelAI.Benchmark -- --corpus <corpus-dir> --out report.md
```

A worked example ships with the tool, so the report's shape can be seen without the real corpus:

```bash
dotnet run --project tools/SentinelAI.Benchmark -- --corpus tools/SentinelAI.Benchmark/sample-corpus
```

| Flag | Meaning |
|---|---|
| `--corpus <dir>` | The benchmark corpus. Required. |
| `--out <file.md>` | Also write the Markdown report to a file. |
| `--json <file.json>` | Write the raw per-category scores, for a chart or a spreadsheet. |
| `--window <n>` | Line tolerance when matching a report to a label. Default 3; `0` is exact. |

Exit codes: `0` report produced, `1` bad arguments, `2` the corpus could not be read.

## Corpus layout

```
<corpus>/
  corpus.json              name and version, for the report header
  labels/*.json            GroundTruthLabel[] — one file per project, or one for all
  results/sentinelai.json  ToolFinding[] or SARIF
  results/sonarqube.sarif  SARIF
  results/snyk.sarif       SARIF
```

The tool name comes from the **file name**, so adding a fourth tool to the comparison is dropping
a file into `results/`, not editing the reader. Both result shapes are accepted because the three
tools do not agree on one: SonarQube and Snyk export SARIF, and SentinelAI's own findings come out
of its read API in its own JSON. Which one a file is gets decided by looking inside it, not by its
extension — exports get renamed, and a `.json` holding SARIF read as an empty array is the failure
that looks like a tool finding nothing.

**The corpus is never embedded.** `CorpusReader` reads and nothing else: no Qdrant client, no
embedder, no write path of any kind. SEC-38's "separate store, never embedded into RAG" holds here
by construction.

## The label format

```json
{
  "id": "terragoat-iam-01",
  "project": "terragoat",
  "file": "infra/iam.tf",
  "line": 25,
  "category": "CWE-284",
  "is_vulnerable": true,
  "note": "Inline policy grants s3:* on Resource '*' to the order task role."
}
```

**Both polarities are labels.** A corpus of only-vulnerable places can measure recall and cannot
measure precision: nothing tells the scorer that a report at line 120 is *wrong* rather than
something the labellers had not reached yet. `"is_vulnerable": false` is a positive statement that
a place is clean, and it is what makes a false positive distinguishable from an unlabelled one.

`line: 0` means the label is about the file as a whole and matches a report anywhere in it.

## How a report is matched to a label

All four of **project, file, category, and line-within-window** must agree.

Dropping any one changes what the number means:

- **Without the project**, two corpus projects that both have `infra/main.tf` cross-contaminate.
- **Without the category**, a logging warning reported on the same line as an IAM escalation counts
  as having found it — the easiest way there is to manufacture a good recall figure.
- **With an exact line**, Checkov (which reports at the offending attribute) and Snyk (which
  reports at the enclosing `resource` block) score as having missed issues they both found, and
  recall becomes a measure of line-numbering convention.

The window is **±3 lines** by default — the span of the block a finding is normally reported
within. Wide enough to swallow a file would turn precision into "did the tool say anything about
this file", which every scanner wins.

Matching is a **greedy one-to-one pairing**, nearest line first. Tools emit several rules against
one weakness — Checkov alone reports a wildcard IAM policy under more than one check id — so
without this a tool with more rules per weakness out-scores one that detects exactly the same
things.

## The one decision that matters most

**A report at a place the corpus does not label is neither a true nor a false positive.** It is
excluded from precision entirely and counted separately.

Counting these as false positives would punish the tool that looks hardest, and would turn
precision into a measure of how completely the corpus was labelled rather than of how right the
tool is.

It is not free, and the report does not pretend otherwise: **a tool that reports a thousand
unlabelled findings and two labelled correct ones scores 100% precision.** That is exactly why the
unlabelled count sits in the same table as the ratio, in its own column. Read them together or not
at all.

## Why precision and recall are always printed together

The ticket asks for precision as the false-positive headline and recall as the guardrail, and the
reason for the pairing is that either can be bought with the other:

- report one certain finding → 100% precision;
- report everything → 100% recall.

So the renderer never emits one without the other, and every per-category cell carries `n=`, the
number of judgeable observations behind it. `100%` over one label and over four hundred are
different claims, and a table of bare percentages hides which one you are reading.

Two conventions worth knowing:

- **A tool that reported nothing scores precision 1, recall 0.** It has said nothing false;
  silence is punished in recall. That division of labour is the point of reporting both.
- **A category with no vulnerable labels scores recall 1.** Every one of its zero vulnerabilities
  was found. Returning 0 would make a deliberately-clean category look like a total failure.

## The caveats are generated, not typed

`BenchmarkScorer` computes the "How to read this" section from the data. A caveat someone wrote
once goes stale the first time the corpus changes; one computed from the labels stays true, and
appears only when it applies.

Four of them:

| Caveat | Fires when |
|---|---|
| Matching rule and window | always — the figures cannot be reproduced without it |
| Unlabelled findings excluded | always — see above |
| **The C# ground-truth gap** | any label on a `.cs` file |
| Projects scanned but never labelled | a tool reported in a project with no labels |
| Categories with fewer than five vulnerable labels | any thin category |

The C# one is the load-bearing case, and SEC-38 names it explicitly: **there is no C# OWASP
Benchmark**, so the C# ground truth is small and hand-labelled by this team rather than taken from
a published reference. The caveat states the count, so a reader sees "2 hand-labelled locations
across 1 project" rather than a slogan about limitations. A precision of 100% over six labels is
not the same claim as 100% over six hundred, and a reader who is not told cannot tell.

If a real C# benchmark ever lands, the caveat stops appearing on its own.

## Not a build gate

The runner returns 0 whatever the numbers say. A benchmark that fails a build below some precision
threshold becomes a number people tune, and the figure SEC-39 asks for is the one nobody was
incentivised to move.

## What is covered by tests, and what is not

The scorer is a pure function — no database, no scanner, no file system, no clock — so all 32
tests run without a corpus, a Snyk licence or a SonarQube server. They cover the classification
(TP/FP/FN/unlabelled), the matching rules, one-to-one pairing, path-separator and CWE-spelling
normalisation, the caveat generation, and the SARIF reader.

**What no test here can cover is whether the labels are correct.** That is SEC-38's problem and a
human's. The `note` field on every label exists so a disputed classification can be argued about
by id.

## Reading a competitor's SARIF

`SarifToolFindings` is deliberately *not* `SarifReader` from Infrastructure. That one produces
SentinelAI `Finding`s — tenant, scan job, node reference, severity scale, rule-mapping resolution —
none of which a competitor's export has or needs. Reusing it would mean inventing a tenant id for
Snyk's output, and would let a change to our own normalization silently move our competitors'
scores.

Three things it has to get right, each of whose failure mode is *silence*:

1. **SARIF v1 vs v2.** Checkov still emits v1, where rules live on `run.rules` rather than
   `tool.driver.rules`. Reading only v2 loses every category — findings still appear, with an empty
   category, match no label, and the tool scores zero recall with no error anywhere.
2. **Absolute build-agent paths.** SonarQube reports
   `/home/runner/work/corpus/terragoat/src/App/Shell.cs`. Splitting at the first segment files
   every finding under a project called `home`. The runner therefore passes in the corpus's own
   project names (taken from the labels) and the split happens at the innermost matching segment —
   which also handles `…/terragoat/terragoat/…`, the shape a GitHub Actions checkout produces.
3. **CWE spellings.** `CWE-89`, `cwe_89`, `CWE 89` and SonarQube's zero-padded
   `external/cwe/cwe-089` all normalise to `CWE-89`. Four columns each scoring a quarter of the
   detections is arithmetic that works and an answer that is wrong.

A rule carrying no CWE yields an **empty category** rather than a guess. It matches no label and
shows up as an unlabelled finding, which is the honest place for a report whose weakness class
nobody stated.

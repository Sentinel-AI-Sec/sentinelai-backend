# SentinelAI — full setup on a fresh machine

**What this gets you:** Qdrant and the BGE-M3 embedding service running locally, a real knowledge
corpus loaded, and the whole retrieval stack — **SEC-21 through SEC-25**, plus SEC-48's corpus
boundary — working and provable by tests.

**Time:** ~10 minutes of typing, plus one long image build (the embedder bakes in a 2.2 GB model).

> Retrieval used to work only on the machine that happened to have a Qdrant Cloud key and a model.
> Everything below is that setup, turned into commands anyone can run.

---

## 0. Prerequisites

| Need | Why | Check |
|---|---|---|
| **Docker Desktop**, running | Qdrant and the embedder are services, not code | `docker ps` |
| **.NET 10 SDK** | builds and tests the backend | `dotnet --version` |
| **Git** | two repos, side by side | `git --version` |
| ~8 GB free disk | the embedder image carries the model | |

**Python is only needed if you plan to re-run the ingest.** Restoring a corpus snapshot — the
normal path — needs no Python at all.

---

## 1. Clone both repositories, side by side

The layout matters: the backend's compose file builds the embedder from `../sentinelai-knowledge`,
so they must be siblings.

```bash
mkdir SentinelAI && cd SentinelAI
git clone https://github.com/Sentinel-AI-Sec/sentinelai-backend.git
git clone https://github.com/Sentinel-AI-Sec/sentinelai-knowledge.git
```

```
SentinelAI/
├─ sentinelai-backend/     ← you run commands from here
└─ sentinelai-knowledge/   ← corpus + embedding service live here
```

---

## 2. Start the knowledge stack

From `sentinelai-backend`:

```bash
docker compose -f compose.knowledge.yaml up -d qdrant
```

That is Qdrant on **6334** (gRPC — what the .NET client speaks) and **6333** (REST — what `curl`
and the dashboard use). Storage is a named volume, so the corpus survives `down`.

Now the embedder. **This build takes 10–25 minutes the first time** — it installs the CPU-only
torch wheel and bakes in BGE-M3 at its pinned revision, so that no query ever pays a 2.2 GB
download:

```bash
docker compose -f compose.knowledge.yaml --profile full up -d --build embedder
```

> **Want a fast build?** `docker compose -f compose.knowledge.yaml build --build-arg PRELOAD_MODEL=false embedder`
> skips baking the weights; the model then downloads on first use instead. Fine locally, wrong for
> anything shared.

Check both:

```bash
curl http://localhost:6333/readyz
curl http://localhost:7860/health
```

The embedder loads the model **lazily**, so the first `/health` answers instantly and the first
real embed takes a minute or two. That is deliberate — see §7.

### Do I need the embedder at all?

**No, and this is a supported configuration.** Every finding carrying a CVE or CWE is answered by
a Qdrant payload filter with no model involved. Skip the embedder and:

- SEC-22's **exact** arm works, SEC-23, SEC-24 and SEC-48 all work
- SEC-22's **semantic** and **hybrid** arms report an honest miss instead of guessing
- SEC-25 reports 100% grounding coverage *and* names semantic/hybrid as modes that never fired

Run `up -d qdrant` alone and everything except modes 2 and 3 is exercised.

---

## 3. Load a corpus

Qdrant is running and **empty**. Confirm:

```bash
./scripts/corpus.sh status          # PowerShell: ./scripts/corpus.ps1 status
```

```
Qdrant at http://localhost:6333
  offense         0 points  <- empty. restore, or run the ingest
  defense         0 points  <- empty. restore, or run the ingest
```

### 3a. Restore a snapshot — the normal path

Someone who already has the corpus runs:

```bash
./scripts/corpus.sh snapshot
```

That writes two `.snapshot` files into `.corpus/snapshots/`. Share that folder (it is git-ignored —
it is ~130 MB of vectors, not source). On your machine, drop them into `.corpus/snapshots/` and:

```bash
./scripts/corpus.sh restore
```

```
  offense     28950 points  (expected)
  defense     31179 points  (expected)
```

**Why snapshots rather than everyone re-ingesting:** the ingest wants source data and a GPU, takes
an afternoon, and produces a corpus with a *different* `corpus_version`. SEC-48 then treats those
as different corpora — correctly. A snapshot is the same bytes everywhere, so every machine
retrieves against one corpus and audits stay comparable.

### 3b. Build one from scratch — only if you must

In `sentinelai-knowledge`: install with the `embed` extra, fetch the sources, and run the notebook
through the Qdrant cells. It writes `out/corpus_manifest.json`, which §4 points the backend at.

---

## 4. Configure the backend

```bash
cp src/SentinelAI.Api/appsettings.Development.example.json src/SentinelAI.Api/appsettings.Development.json
```

**The template already points at the local stack** — `localhost:6334` for Qdrant,
`localhost:7860` for the embedder, and the sibling repo's manifest. If you followed §1–§3 there is
nothing to edit.

```json
"Knowledge": {
  "Endpoint": "http://localhost:6334",
  "ApiKey": "",
  "Manifest": {
    "Path": "../sentinelai-knowledge/out/corpus_manifest.json",
    "FailFastOnMismatch": true
  },
  "Embedder": { "BaseUrl": "http://localhost:7860", "ApiKey": "" }
}
```

Two things to know:

- **`appsettings.Development.json` is git-ignored.** The template is tracked; your file is not.
  Never put a key in the template.
- **Set `SentinelAI:Models:Provider` to `"Scripted"`** unless you have model credentials. The
  template ships `"Nim"` with blank keys and a live provider with no key refuses to boot. That
  refusal is the feature; it will still stop you if you skip this.

No embedder? Set `"BaseUrl": ""`. That is a configuration, not a degradation.

---

## 5. Verify — this is the part that matters

```bash
dotnet test SentinelAI.slnx
```

| What you have | Expect |
|---|---|
| Nothing but the code | **~770 passed, ~31 skipped, 0 failed** |
| \+ Docker (§2) | \+8 adapter tests |
| \+ a corpus (§3) | \+17 live-corpus tests |

**Skips are not failures.** Each says what it needs. The six that always skip need the
`sentinelai-fixtures` repo and belong to a different story.

### Per-story checks

```bash
# SEC-21  query construction + attack-graph handoff
dotnet test tests/SentinelAI.Application.Tests --filter "FullyQualifiedName~RetrievalQueryBuilder|FullyQualifiedName~QueryTextSanitizer|FullyQualifiedName~AttackGraphHandoff"

# SEC-22  the decision tree, and both mandatory filters
dotnet test tests/SentinelAI.Application.Tests --filter "FullyQualifiedName~KnowledgeRetrievalServiceTests|FullyQualifiedName~RetrievalContractTests"

# SEC-23  offense/defense split
dotnet test tests/SentinelAI.Application.Tests --filter "FullyQualifiedName~AgentRetrievalTests"

# SEC-24  deprecated / low-quality filtering
dotnet test tests/SentinelAI.Application.Tests --filter "FullyQualifiedName~ChunkQualityTests|FullyQualifiedName~LowQualityFilteringTests"

# SEC-25  grounding coverage + per-mode fire rates
dotnet test tests/SentinelAI.Application.Tests --filter "FullyQualifiedName~RetrievalEvaluationTests"

# SEC-48  corpus boundary: same-model invariant + version stamp
dotnet test tests/SentinelAI.Application.Tests --filter "FullyQualifiedName~CorpusParityTests"
dotnet test tests/SentinelAI.Infrastructure.Tests --filter "FullyQualifiedName~CorpusBoundaryTests"
dotnet test tests/SentinelAI.Integration.Tests --filter "FullyQualifiedName~AuditCorpusStampTests"

# Everything above, against the REAL corpus (needs §3)
dotnet test tests/SentinelAI.Integration.Tests --filter "FullyQualifiedName~LiveCorpus"
```

### The one-command proof that the corpus is real

```bash
curl -s -X POST "http://localhost:6333/collections/offense/points/count" \
  -H "Content-Type: application/json" \
  -d '{"exact":true,"filter":{"must":[{"key":"cwe_id","match":{"value":"CWE-502"}}]}}'

curl -s -X POST "http://localhost:6333/collections/offense/points/count" \
  -H "Content-Type: application/json" \
  -d '{"exact":true,"filter":{"must":[{"key":"cwe_id","match":{"value":"CWE-502"}},{"key":"source","match":{"value":"CWE"}}]}}'
```

**825 versus 2.** Without the `source` condition you get 825 CVEs that merely *mention* CWE-502
instead of the two chunks that define it — and they look like perfectly good results. That
measurement is why `ExactLookup` has no public constructor.

---

## 6. Prove the A↔B boundary (SEC-48)

The invariant: *the model that indexed the corpus must be the model that queries it.* A mismatch
produces confident, meaningless results **and no error** — so it is checked at startup.

On boot you get one of three lines:

| Log | Means |
|---|---|
| `A-to-B boundary verified: corpus '…' was built by BAAI/bge-m3 @ 5617a9f6…` | Proven |
| `usable but not fully proven: [RevisionNotPinned] …` | Nothing wrong, something unchecked |
| **Startup throws** `… are not the same pairing` | Known-wrong. Fix it, don't bypass it |

To move from *unproven* to *proven*, the corpus manifest must carry a pinned revision and a parity
baseline. Record the baseline from the running embedder:

```bash
curl -s http://localhost:7860/parity
```

```json
{ "backend": "bge", "dim": 1024, "sparse": true, "norms": [17.48…, 19.20…, 18.05…] }
```

Those `norms` are what the ingest's `parity_check()` produced. When the manifest carries them, the
boundary is verified by **reproducing numbers the model made** rather than by comparing strings a
human typed — which is the only check that survives an upstream re-release under an unchanged
model name.

`FailFastOnMismatch: false` downgrades the refusal to an error log. Use it only when you know why
a mismatch is safe.

---

## 7. Things that will confuse you, in the order you will hit them

| Symptom | Cause | Fix |
|---|---|---|
| `protocol error` from Qdrant | you used 6333 | the .NET client is gRPC → **6334** |
| `Bind for 0.0.0.0:6333 failed: port is already allocated` | an older `qdrant-test` container | `docker rm -f qdrant-test` |
| `The 'offense' collection does not exist` | Qdrant is up but empty | §3 |
| First embed hangs ~2 min, then works | the model loads lazily on first use | expected; `curl -X POST localhost:7860/warmup` to pay it up front |
| `Provider 'Nim' is configured but … no API key` | template copied unchanged | set `Provider` to `Scripted` |
| Tests say `No corpus configured` and skip | no `appsettings.Development.json` | §4 |
| `SeedKnowledgeRetriever answered … from canned data` | no `Knowledge:Endpoint` | §4 — you are on the stub, not the corpus |
| Ingest and query disagree on model | SEC-48 caught a real mismatch | §6 — do not disable the check |

### These tests delete collections

`QdrantKnowledgeSearchTests` creates and drops collections named exactly `offense` and `defense`.
**Point them at a throwaway instance, never at a corpus you care about.** There is a guard — the
run refuses if either collection holds more than 64 points — but do not rely on it.

If you restored a real corpus in §3, that guard is what protects it. It has been enough so far;
it is not a reason to be careless.

---

## 8. Shutting down

```bash
docker compose -f compose.knowledge.yaml down          # keeps the corpus
docker compose -f compose.knowledge.yaml down -v       # discards it — you will re-restore
```

---

## 9. Where the design is written down

| Doc | Covers |
|---|---|
| [`docs/Retrieval.md`](docs/Retrieval.md) | SEC-22/23 — the decision tree and both mandatory filters |
| [`docs/Deprecated_Filtering.md`](docs/Deprecated_Filtering.md) | SEC-24 — over-fetch-and-filter, and the rule deliberately *not* applied |
| [`docs/Retrieval_Evaluation.md`](docs/Retrieval_Evaluation.md) | SEC-25 — why one number was not enough |
| [`docs/Knowledge_Setup.md`](docs/Knowledge_Setup.md) | the shorter, test-focused version of this page |
| `../sentinelai-knowledge/service/README.md` | the embedding service itself, and deploying it to a free HuggingFace Space |
| `PIPELINE_A_CONTEXT.md` (Docs-main) | the corpus: payload schema, the measured traps, the same-model rule |

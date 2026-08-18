# Working on retrieval (SEC-22 → SEC-25)

**Read this if** you have cloned the repo and want to run, change, or review the retrieval code.

Three things retrieval depends on are **not in this repository**, so a fresh clone cannot exercise
it. That is deliberate, and this page is how you close the gap.

> Related, and different: [`Configuration.md`](Configuration.md) §6 is the settings reference —
> what each key does. [`Retrieval.md`](Retrieval.md) is the design — why the code is shaped the
> way it is. This page is the setup.

---

## 1. What is missing from your clone, and why

| Missing | Why it is not committed | Size |
|---|---|---|
| `src/SentinelAI.Api/appsettings.Development.json` | Holds a corpus URL and API key. Git-ignored (`.gitignore` line 9) — a credential in a tracked file is a credential you have leaked. | tiny |
| A running **Qdrant** | A service, not code. Started per machine. | container |
| The **corpus** — 32,432 chunks | Produced by the `sentinelai-knowledge` repo from NVD, CWE, ATT&CK, CAPEC and OWASP. Data, not source. | ~130 MB of vectors |
| The **embedding service** | Optional. Wraps a 2.2 GB model; only needed for meaning-based search. | ~2.2 GB image |

---

## 2. The default experience is green, with skips

Clone, build, test. Nothing else.

```bash
dotnet test SentinelAI.slnx
```

**Expect 851 passed and 31 skipped.**

The skips are **not** breakage. Twenty-five of them need infrastructure you do not have yet, and
they say so:

```
No Qdrant reachable. Run `docker run -p 6334:6334 qdrant/qdrant`, or set SENTINELAI_QDRANT, ...
No corpus configured. Set Knowledge:Endpoint in appsettings.Development.json ...
```

The other six are `CommittedFixtureGranularityTests`, which need the `sentinelai-fixtures`
repository checked out; they belong to a different story.

**Everything that can be tested without infrastructure already is.** The decision tree, both
mandatory filters, the CWE fallback, the embedder's failure modes, the offense/defense split,
SEC-24's quality guard and SEC-25's coverage metric are all covered by the 810 — because the logic
lives in `Application` and the network lives behind two ports.

---

## 3. Level 1 — the adapter tests · Docker only · ~5 minutes

This turns on the eight tests that prove the Qdrant filters behave against a real index rather
than against a fake.

```bash
docker run -d --name qdrant-test -p 6333:6333 -p 6334:6334 qdrant/qdrant
```

That is the whole setup. **No configuration.** The tests probe `localhost:6334` and run if
anything answers.

```bash
dotnet test tests/SentinelAI.Integration.Tests --filter "FullyQualifiedName~QdrantKnowledgeSearchTests"
```

**Expect 8 passed** (~20 s — it seeds and tears down real collections each time).

> ### These tests delete collections
>
> They create and drop collections named exactly `offense` and `defense`. **Point them at a
> throwaway instance, never at a corpus you care about.** There is a guard — the run refuses if
> either collection already holds more than 64 points — but do not rely on it as permission to be
> careless.

Clean up with `docker rm -f qdrant-test`.

---

## 4. Level 2 — a real corpus · ~15 minutes + an ingest

This turns on the seventeen tests that prove retrieval reaches Pipeline A's knowledge, that a whole
scan is grounded in it rather than in the walking skeleton's canned text, and that grounding
coverage on the fixture is what SEC-25 says it is.

### 4.1 Get a corpus

Either point at a cluster a teammate has already filled, or build one:

1. In the `sentinelai-knowledge` repo, run the notebook through Part 7 (embedding) — this is the
   expensive step and wants a GPU.
2. Run its Qdrant cells (85–88) against a reachable cluster. Colab cannot see your laptop, so use
   Qdrant Cloud's free 1 GB tier if you are embedding there; ~130 MB of vectors fits comfortably.
3. Confirm what landed — trust the server, not the upload log:

```bash
curl.exe -s -H "api-key: $KEY" "$URL:6333/collections/offense/points/count" -X POST -H "Content-Type: application/json" -d '{"exact":true}'
```

A healthy corpus reports **offense 28,950** and **defense 31,179**.

### 4.2 Point the backend at it

Copy the template and fill in the `Knowledge` section:

```bash
cp src/SentinelAI.Api/appsettings.Development.example.json src/SentinelAI.Api/appsettings.Development.json
```

```json
"Knowledge": {
  "Endpoint": "https://<cluster>.cloud.qdrant.io:6334",
  "ApiKey": "<your key>",
  "Embedder": { "BaseUrl": "" }
}
```

> **Port 6334, not 6333.** The .NET client speaks gRPC; 6333 is the REST port and pointing at it
> gives a protocol error rather than a message about the wrong port.

> **Also set `SentinelAI:Models:Provider` to `"Scripted"`.** The example template ships `"Nim"`
> with blank keys, and a live provider with no key refuses to boot (SEC-30). That refusal is the
> feature, but it will stop you if you copy the file unchanged.

The tests read `Knowledge:Endpoint` straight out of that file, so there is **no environment
variable to remember**. `SENTINELAI_CORPUS_URL` / `SENTINELAI_CORPUS_KEY` still override it if you
want a one-off.

```bash
dotnet test tests/SentinelAI.Integration.Tests --filter "FullyQualifiedName~LiveCorpus"
```

**Expect 17 passed.** These only ever read — unlike level 1, they create and delete nothing.

---

## 5. Level 3 — the embedding service · optional

Only needed for findings that carry **neither a CWE nor a CVE**. Everything with an identifier is
answered by a payload filter with no model involved.

Without it, id-less findings record an honest miss (`no embedding model is configured`) instead of
falling back to invented text or crashing the scan. That is a supported configuration, not a
degraded one.

Setup is in the sibling `sentinelai-knowledge` repository, at `service/README.md`; then set
`Knowledge:Embedder:BaseUrl`.

> **Nobody has built that image yet.** It is the least-proven part of this feature — expect the
> first `docker build` to need a fix.

---

## 6. Which tests are which

| Filter | Count | Needs | Proves |
|---|---:|---|---|
| `~AgentRetrievalTests` | 9 | nothing | SEC-23 — Red reads offense, Blue reads defense, no per-tool index |
| `~KnowledgeRetrievalServiceTests` | 16 | nothing | The decision tree — every arm, against an in-memory corpus |
| `~RetrievalContractTests` | 31 | nothing | The two mandatory filters are unrepresentable to omit |
| `~RetrievalWiringTests` | 6 | nothing | Configuration decides real-corpus vs stub |
| `~ChunkQualityTests` | 30 | nothing | SEC-24 — what the quality guard drops, keeps, and over-fetches |
| `~LowQualityFilteringTests` | 7 | nothing | SEC-24 — the guard is on both arms and `k` results still come back |
| `~RetrievalEvaluationTests` | 11 | nothing | SEC-25 — grounding coverage, per-mode fire rates, the arithmetic |
| `Infrastructure.Tests.Knowledge` | 23 | nothing | The embedder adapter's failure modes |
| `~QdrantKnowledgeSearchTests` | 8 | **Docker** | The adapter's filters against real Qdrant |
| `~LiveCorpus` | 17 | **corpus** | Retrieval, a whole scan, SEC-24's guard and SEC-25's coverage against Pipeline A's knowledge |

With Docker and a corpus, the full suite is **876 passed, 6 skipped**, and the retrieval
slice above is **157 passed, 0 failed**.

> **One unrelated failure is currently expected.**
> `IngressRedactionWiringTests.The_registered_debate_engine_is_the_redacting_one` asserts that
> `IDebateEngine` resolves to exactly `RedactingDebateEngine`. SEC-50 now wraps that in
> `EdgeIntegrityDebateEngine`, deliberately and by its own comment, so the assertion is stale
> rather than the redaction being gone — the redacting engine is still in the chain. It fails
> on `origin/dev` independently of anything on this page.

---

## 7. See the rule that justifies all of this

One pair of queries against any real corpus. This is the measurement the whole design rests on:

```bash
# cwe_id=CWE-502, no source condition
curl.exe -s -H "api-key: $KEY" -X POST "$URL:6333/collections/offense/points/count" -H "Content-Type: application/json" -d '{"exact":true,"filter":{"must":[{"key":"cwe_id","match":{"value":"CWE-502"}}]}}'
```

```bash
# the same, plus source=CWE — what the code always sends
curl.exe -s -H "api-key: $KEY" -X POST "$URL:6333/collections/offense/points/count" -H "Content-Type: application/json" -d '{"exact":true,"filter":{"must":[{"key":"cwe_id","match":{"value":"CWE-502"}},{"key":"source","match":{"value":"CWE"}}]}}'
```

**825 versus 1.** Without the source condition you get 825 CVEs that merely *mention* CWE-502
instead of the one chunk that defines it — and they look like perfectly good results. That is why
`ExactLookup` has no public constructor: the source condition cannot be left off.

---

## 8. Messages you will actually hit

| What you see | What it means | Fix |
|---|---|---|
| `SeedKnowledgeRetriever answered ... from canned data` | You are on the stub — no corpus configured | Set `Knowledge:Endpoint` |
| `No Qdrant reachable` (skip) | No container running | `docker run -p 6334:6334 qdrant/qdrant` |
| `No corpus configured` (skip) | No `appsettings.Development.json`, or no `Knowledge:Endpoint` in it | §4.2 |
| `The 'offense' collection does not exist` | Qdrant is up but empty | Ingest the corpus |
| `already holds N points ... run has been stopped` | You aimed the adapter tests at a real corpus | Use a throwaway instance |
| `Provider 'Nim' is configured but ... have no API key` | You copied the example settings unchanged | Set `Provider` to `Scripted` |
| protocol error from `6333` | The client speaks gRPC | Use `6334` |

---

## 9. Reviewing the code

Two files carry the design; read them first and the rest follows.

- **`ExactLookup.cs`** — no public constructor. The 825-versus-1 above, made unrepresentable.
- **`SemanticQuery.cs`** — throws if given no filter. Unfiltered, 26,283 NVD chunks outrank 172
  OWASP ones for every query.

Then `KnowledgeRetrievalService.cs` (the tree), `RetrievalIntent.cs` (the filter table),
`AgentRetrieval.cs` (SEC-23, one file), `ChunkQuality.cs` (SEC-24 — see
[`Deprecated_Filtering.md`](Deprecated_Filtering.md)), and `RetrievalEvaluation.cs` (SEC-25 — see
[`Retrieval_Evaluation.md`](Retrieval_Evaluation.md)).

**Retrieval has no HTTP endpoint.** Nothing calls `ThinSlicePipeline` from a controller yet, so
there is no request to send — SEC-46 is the story that wires scan-time orchestration. The evidence
for these stories is the test suite, not a curl.

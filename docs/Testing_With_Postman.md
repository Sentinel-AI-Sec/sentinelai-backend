# Driving the pipeline from Postman (no GitHub Action)

How to get from a cold API to candidate exploit chains, using the committed fixture instead of
a real Action run. Five requests, one script.

The Action's job is to run the scanners on a runner and package their output. The fixture
already ships that output in `scan_out/`, so locally the whole thing reduces to packaging.

---

## 0. What you need

- The API running (`dotnet run --project src/SentinelAI.Api`, or `docker compose up`).
- A database with migrations applied. `MakeChainHopFindingOptional` is required — without it
  every chain write fails on a `finding_id` NOT NULL constraint:
  ```
  dotnet ef database update --project src/SentinelAI.Infrastructure --startup-project src/SentinelAI.Api
  ```
- The fixture repo checked out beside this one (`../sentinelai-fixtures`).
- `postman/SentinelAI.postman_collection.json` imported. Set `baseUrl` to your host.

> `postman/` is gitignored, so the collection is yours locally — a request added there does not
> reach your teammates. The bundle script lives in `scripts/` for that reason.

---

## 1. Get a token

**Auth → Register**, then **Auth → Login**. The collection's test script stores `accessToken`
for you.

The token must carry the **`scan:write`** scope: ingest needs it, and so does the graph stage,
which writes node, edge and chain rows.

## 2. Have a project to scan

Ingest resolves `metadata.project_id` **tenant-scoped**. A project id belonging to another
tenant returns the same 404 as one that does not exist (deliberately — a 403 would confirm it
exists). There is no project-creation endpoint yet, so insert one directly:

```sql
INSERT INTO Projects (Id, TenantId, RepoUrl, DefaultBranch)
VALUES ('11111111-1111-1111-1111-111111111111', '<your tenant id>',
        'https://github.com/Sentinel-AI-Sec/sentinelai-fixtures', 'main');
```

Your tenant id is the `tenant_id` claim in the token you just got.

## 3. Build a bundle from the fixture

```bash
bash scripts/build-fixture-bundle.sh 11111111-1111-1111-1111-111111111111
```

It writes `postman/bundle.tar.gz` and prints the `metadata.json` it generated. What it assembles:

| In the bundle | From the fixture | Why |
|---|---|---|
| `findings/*.sarif` | `scan_out/` | The scanners' output. **Filenames matter** — the normalizer routes each file to an extractor by prefix (`roslyn`, `osv`, `trivy`, `checkov`). |
| `graph-inputs/infra/*.tf` | `infra/` | The infra spine, the IAM grants, the task definition |
| `graph-inputs/Dockerfile` | repo root | The code→infra image-name join |
| `graph-inputs/src/OrderApp/packages.lock.json` | the project | The dep→code seam |
| `metadata.json` | generated | Provenance. `artifacts` is cross-checked: list a file the tarball lacks and ingest returns 422. |

No `.cs` ever goes in. The backend refuses any bundle carrying application source
(`docs/Bundle_Ingest.md` §5), and the script only copies whitelisted patterns — the same
whitelist the Action uses.

**With `terraform` on your PATH** the script also runs `terraform init && terraform graph` and
includes the real DOT dependency graph. Without it, the backend falls back to parsing the `.tf`
sources — a documented degraded path (SEC-17 step 4), not a failure. Both produce the flagship
chain.

## 4. Submit it

**Scans → Submit Scan Bundle**

- `Metadata` (text): paste what the script printed.
- `Bundle` (file): select `postman/bundle.tar.gz`.

Expect `202 Accepted`. The test script captures `scanJobId` into a collection variable.

Ingest does not scan anything — it accepts, refuses source, records provenance, returns. A web
request cannot block on a scan (`docs/Bundle_Ingest.md` §1).

## 5. Run the graph stage

**Scans → Run Graph Stage (candidate chains)** → `POST /v1/scans/{{scanJobId}}/graph`

This is the manual trigger: normalize (SEC-14/15/16) → the four seams (SEC-17/18/19) →
decorate and traverse (SEC-20), synchronously, returning the chains. It is fast — parsing and
graph traversal, no model calls.

It exists because **no queue-driven worker does this yet**. When one lands it calls the same
`GraphStagePipeline` and this endpoint becomes redundant. Same reasoning as
`POST /v1/debates/demo`.

### What a good response looks like

```jsonc
{
  "isSuccess": true,
  "data": {
    "findings": 47,
    "terraformFiles": 5, "lockFiles": 1, "dockerfiles": 1,
    "candidateChains": 6,
    "chains": [
      {
        "priority": 1,
        "hopCount": 4,
        "minConfidence": "Inferred",
        "maxSeverity": 4,
        "path": [
          "pkg:newtonsoft.json",
          "code:orderapp",
          "task:order_task",
          "iam_role:order_task_role",
          "s3:customer_data"
        ],
        "hops": [
          { "order": 0, "nodeKey": "pkg:newtonsoft.json", "tactic": "InitialAccess",       "relation": null,          "confidence": null },
          { "order": 1, "nodeKey": "code:orderapp",       "tactic": "Execution",           "relation": "used-by",     "confidence": "Certain" },
          { "order": 2, "nodeKey": "task:order_task",     "tactic": "Persistence",         "relation": "deployed-as", "confidence": "Inferred" },
          { "order": 3, "nodeKey": "iam_role:order_task_role", "tactic": "PrivilegeEscalation", "relation": "assumes", "confidence": "Certain" },
          { "order": 4, "nodeKey": "s3:customer_data",    "tactic": "Collection",          "relation": "can-access",  "confidence": "Certain" }
        ]
      }
    ],
    "disclaimer": "Candidate chains only: ..."
  }
}
```

That first chain is the fixture's golden chain. `minConfidence` is `Inferred` because the
`deployed-as` hop rests on an image-name match — one weak join drags the whole chain down, which
is the point (AID-01 §3.3). The collection's test script asserts exactly this, so a red test tab
tells you which part regressed.

You should also see a chain through `task:legacy_worker_task` at `Unresolved` — the fixture's
deliberate ambiguous join, recorded rather than dropped.

## 6. Poll the job

**Scans → Get Scan Job (Poll)** now reports `stage: Graph`. On failure it reports
`status: Failed` with `failureReason` — the stage records where it got to, so the row is not
left silently at its old stage.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `candidateChains: 0`, `terraformFiles: 0` | The bundle has no `graph-inputs/`. Rebuild with the script; a hand-rolled tarball usually has the wrong root. |
| `candidateChains: 0`, inputs non-zero | Nothing became a **hot seed** — no finding at severity ≥ 3 landed on a structural node. Check `findings` is non-zero first; if it is 0, the `findings/` filenames are wrong (see step 3). |
| Chain stops at `code:orderapp` | The Dockerfile carries no `LABEL org.sentinelai.image`, so the code→infra seam had nothing to compare. It is in the fixture; a different repo needs one adding. |
| `422` on submit | Either `metadata.artifacts` lists a file the tarball lacks, or a source file got in. The message names which. |
| `404` on submit | The `project_id` is not a project **your tenant** owns. |
| `409` on the graph stage | The job has no stored bundle. |
| `410` on the graph stage | The bundle was purged. |
| `500` on the graph stage, `finding_id` constraint | Migrations are behind — apply `MakeChainHopFindingOptional`. |

---

## Where the same thing is covered by tests

You do not need any of the above to verify the chain logic — it is pinned offline:

| Test | What it proves |
|---|---|
| `FlagshipChainTests` | Every real reader/writer/unifier/locator/decorator/traverser over the fixture's own Terraform produces the flagship chain at `Inferred` |
| `BundleToChainsTests` | A real `.tar.gz` on disk, through the real bundle store, becomes those chains |
| `GraphStagePipelineTests` | The bundle layout is sorted correctly, including Dockerfile-to-project attribution |
| `RunGraphStageCommandHandlerTests` | The endpoint's auth, tenant, purge and failure paths |

`dotnet test` runs the lot in about four seconds.

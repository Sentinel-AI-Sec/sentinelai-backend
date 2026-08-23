# Read API (SEC-40)

The endpoints a screen reads a scan's results from: findings, the graph, the chains, the report
and the bundle's provenance.

**If you are building the Angular screen (SEC-42), this page is the contract.** The shapes here
match `SentinelAI_API_Design_V2.1.md` §5.3–5.5 and are pinned by
`ReadApiContractTests` — a rename breaks that test before it breaks your screen.

---

## 1. The endpoints

| Method | Route | Scope | Paged |
|---|---|---|---|
| GET | `/v1/scans` | `scan:read` | ✅ |
| GET | `/v1/scans/{id}/summary` | `scan:read` | — |
| GET | `/v1/scans/{id}/bundle` | `scan:read` | — |
| GET | `/v1/scans/{id}/findings` | `scan:read` | ✅ |
| GET | `/v1/scans/{id}/graph` | `scan:read` | — (capped) |
| GET | `/v1/scans/{id}/chains` | `scan:read` | ✅ |
| GET | `/v1/reports` | `report:read` | ✅ |
| GET | `/v1/reports/{id}` | `report:read` | — |
| POST | `/v1/scans/{id}/audit` | `scan:write` | — |

The last one is not a read endpoint. See §6.

`GET /v1/scans`, `GET /v1/reports` and `GET /v1/scans/{id}/summary` were added after the original
SEC-40 set and answer in exactly the same format — see §3.1 and §3.2 for why they exist.

---

## 2. Three things that differ from the rest of this API

These endpoints deliberately do not look like `GET /v1/scans/{id}` and the others. The reason
is that the frontend was given `SentinelAI_API_Design_V2.1.md`, and that document is the
contract another repository is already coding against.

| | Older endpoints | Read API |
|---|---|---|
| Success body | `{ "isSuccess": true, "data": {…} }` | the payload, bare |
| Casing | `camelCase` | `snake_case` |
| Enums | numbers (`"layer": 0`) | words (`"layer": "code"`) |
| Errors | the same envelope | RFC 7807 `problem+json` |

Enums as words is not cosmetic: `"confidence": 2` means nothing to a renderer, and it silently
changes meaning the day a member is inserted into the enum. `"certain"` does neither.

Two error formats in one API is a real inconsistency. It is contained on purpose — converting
the whole API would change responses for auth, ingest and project endpoints that other work
depends on mid-sprint.

---

## 3. Shapes

### 3.1 `GET /v1/scans` and `GET /v1/reports` — the lists

SEC-40 shipped reads addressed by id and nothing that enumerates them. The console's
`core/history/recents.ts` recorded the consequence in its own header: with no way to list, the
dashboard substituted *a browser-local index of the ids this browser happened to open* — not the
tenant's history, but one machine's memory of it, lost on a cache clear and invisible to a
colleague. These two close that.

```json
{
  "items": [
    { "scan_job_id": "7d4e…", "project_id": "b21f…",
      "repo_url": "https://github.com/org/repo", "pr_ref": "pr/42", "commit_sha": "abc123",
      "status": "completed", "stage": "report", "report_id": "a91c…",
      "bundle_purged": true, "corpus_version": "2026-07-15", "failure_reason": null,
      "started_at": "2026-08-19T10:03:11Z", "completed_at": "2026-08-19T10:05:40Z" }
  ],
  "next_cursor": "AQIDBA…", "limit": 50
}
```

**Newest first** — the opposite of `/findings` and `/chains`, which page through the contents of
one scan in the order the rows were written. These page through history, and the first page a
person wants is the most recent one.

- `GET /v1/scans` filters with `?project_id=`, `?status=` (`queued|running|completed|failed`) and
  `?stage=` (`received|normalize|graph|retrieve|debate|report`). Filter values are
  case-insensitive; an unknown one is a `400`, not an empty page, for the same reason an unknown
  layer is.
- `GET /v1/reports` filters with `?project_id=`. Its rows carry `report_id`, `scan_job_id`,
  `project_id`, `repo_url`, `pr_ref`, `commit_sha`, `framing`, `summary`, `corpus_version`,
  `retained`, `created_at` and `cost` — **not** the chains, which are the bulk of an audit and the
  reason `GET /v1/reports/{id}` exists.
- `framing` is on every report row. A list is exactly where the draft framing would otherwise get
  dropped, and a screen showing twenty audits with no framing on any of them is where "candidate
  chains a debate argued over" quietly becomes "twenty findings".
- Every row carries `repo_url` and `pr_ref` because **a list of bare GUIDs is not a history.**
  Nobody recognises their own scan by its id.
- `GET /v1/reports` lists audits that were **kept**. A scan whose submitter declined retention
  (SEC-35) ran, was reported on, and is correctly absent — which is why the scan list carries
  `report_id` rather than this being derivable from it.

There is no tenant parameter on either. Every filter narrows; none widens. A `project_id`
belonging to another tenant matches nothing rather than erroring — indistinguishable from a
project that does not exist, the same rule as §7.

### 3.2 `GET /v1/scans/{id}/summary` — the totals paging cannot give

A cursor-paged response knows only what it returned. The console's findings screen therefore
"counts the rows it has loaded, not the scan, because under a cursor it cannot honestly claim the
latter" — and a page count next to a filter answers "how many have I fetched" while every reader
parses it as "how many are there". This endpoint is where the real number comes from.

```json
{
  "scan_job_id": "7d4e…", "status": "completed", "stage": "report", "report_id": "a91c…",
  "findings": {
    "total": 128, "max_severity": 4, "redacted": 3,
    "by_layer": { "code": 61, "dep": 42, "infra": 25 },
    "by_severity": { "0": 4, "1": 19, "2": 55, "3": 38, "4": 12 }
  },
  "graph": {
    "nodes": 214, "edges": 331, "hot_nodes": 12,
    "edges_by_confidence": { "certain": 180, "inferred": 121, "unresolved": 30 }
  },
  "chains": {
    "total": 7, "weakest_join": "unresolved",
    "by_status": { "candidate": 5, "asserted": 1, "validated": 1, "rejected": 0 }
  }
}
```

- **Every bucket is always present, including at zero.** A missing key and a zero are
  indistinguishable to a client, and a filter chip cannot be rendered as "empty" if the API never
  mentions it.
- **Severity is reported as buckets, never as a mean.** Severities are ordinal; the average of a
  4 and two 0s describes nothing.
- **Confidence is three counts, not one score.** `unresolved` is a different statement from
  `inferred`, not a worse one, and any single number mixing them asserts an ordering the rest of
  this product spends its whole UI refusing to assert.
- `max_severity` is `null` — not `0` — when the scan has no findings, because `0` is a real
  severity a finding can carry.
- `chains.weakest_join` is the lowest `min_confidence` across every chain: a ceiling on what the
  scan as a whole can claim.

Every number is a `COUNT` over the same tenant-scoped predicate the corresponding paged endpoint
filters on, so this and a full walk of that endpoint's pages agree by construction —
`The_summary_total_matches_a_full_walk_of_the_paged_findings` pins exactly that.

### `GET /v1/scans/{id}/graph`

Not paginated. **A page of a graph has edges pointing at nodes that are not in it** — the screen
cannot render that and a reader cannot interpret it. Half a graph is not a smaller graph, it is
a wrong one. Bounded by a 5,000-node cap instead; a graph over the cap returns `413` rather
than silently truncating into something that draws as a smaller system than the one scanned.

```json
{
  "scan_job_id": "7d4e…",
  "nodes": [
    { "node_key": "pkg:newtonsoft.json:9.0.1", "type": "pkg", "layer": "dep", "is_hot": true }
  ],
  "edges": [
    { "from": "pkg:newtonsoft.json:9.0.1", "to": "code:orderservice.deserialize",
      "relation": "used-by", "seam": "dep-code", "confidence": "inferred",
      "oriented_attack_dir": true }
  ]
}
```

- `type` — `pkg | code | image | task | role | resource`
- `layer` — `code | dep | infra`
- `confidence` — `certain | inferred | unresolved`
- `seam` — `infra-spine | dep-code | code-infra | role-resource`

> **`type` is not the node-key prefix.** A node keyed `s3:customer-data` has `"type":
> "resource"`. The key prefix is a cross-repo identifier the Action, fixtures and corpus all
> mirror, where `Resource` is historically spelled `s3`; the `type` field is a separate,
> readable vocabulary. Edges address nodes by **key**, not row id, so you can draw the graph
> without building a lookup table first.

### `GET /v1/reports/{id}`

```json
{
  "report_id": "a91c…", "scan_job_id": "7d4e…",
  "framing": "draft_audit",
  "summary": "…", "corpus_version": "2026-07-15", "retained": true,
  "chains": [
    { "id": "…", "priority": 1, "hop_count": 2, "status": "candidate",
      "min_confidence": "inferred",
      "hops": [ { "order": 1, "technique_id": "T1190", "blue_validated": true,
                  "edge_confidence": "inferred", "node_key": "code:…", "finding_id": "…" } ] }
  ],
  "citations": [ { "knowledge_id": "CWE-502", "source": "OWASP", "collection": "offense" } ],
  "cost": { "currency": "USD", "total": 0.0, "model_calls": 4, "rated": true }
}
```

`framing` is always `draft_audit` and it is a field on the wire, not a UI decision. AID-01 §7
makes the framing non-negotiable: this is prioritized material for human review, never a
verified verdict. **Render it.**

`min_confidence` is the weakest join anywhere in the chain. It is the field that stops a chain
resting on a guess being read as certain — show it next to the chain, not in a tooltip.

`cost.rated` false means a tier had no configured price, so `total` is an under-count rather
than the bill.

### `GET /v1/scans/{id}/findings` and `/chains`

```json
{ "items": [ … ], "next_cursor": "AQIDBA…", "limit": 50 }
```

Findings filter with `?layer=code|dep|infra` and `?min_severity=0..4`. An unknown layer is a
`400`, not an empty page — an empty page would read as "this scan has no code findings", which
is a different and wrong answer.

### `GET /v1/scans/{id}/bundle`

Provenance of what the runner uploaded. **It outlives the bundle it describes**: after SEC-35
purges the bytes, the manifest, hash and size stay auditable and `bundle_purged` turns true.
That is how a reader tells "never received" from "received and since deleted".

---

## 4. Pagination

Cursor-based (`?cursor=&limit=`), never `?page=`. With an offset, rows inserted or deleted
between requests shift everything after them — page 2 repeats a row from page 1, or skips one.
A cursor names the last row you actually saw.

- `next_cursor` is `null` on the last page. That, not an item count, is how you know to stop:
  a full page is not evidence more exist.
- `limit` defaults to 50 and is clamped to 200. `?limit=1000000` is otherwise a
  denial-of-service one query long.
- The cursor is opaque. Do not parse it.

It works because every id is `Guid.CreateVersion7()` — UUIDv7 is time-ordered, so ordering by
id is stable and chronological. With random UUIDv4 keys this technique would produce an
arbitrary order and "the next page" would mean nothing.

One nuance worth knowing: UUIDv7 embeds a **millisecond** timestamp, so ids minted inside the same
millisecond are ordered randomly among themselves. Paging is unaffected — keyset paging needs a
total order that is *stable*, and an id is stable whatever it sorts next to, so a page still
cannot repeat or skip a row. What it costs is that rows written in one batch come back in an
arbitrary order among themselves rather than in insertion order.

---

## 5. Errors

RFC 7807 `application/problem+json`:

```json
{ "type": "https://sentinelai.dev/problems/not-found",
  "title": "Resource not found", "status": 404,
  "detail": "no scan job '7d4e…'", "instance": "/v1/scans/7d4e…/findings" }
```

**Branch on `type`, never on `detail`.** Titles and details get reworded; the URI does not.

| `type` suffix | Status | Meaning |
|---|---|---|
| `not-found` | 404 | No such scan/report **or it is not yours** — see §7 |
| `unauthorized` | 401 | No or invalid token |
| `forbidden` | 403 | Token lacks the scope |
| `invalid-request` | 400 | Bad cursor, unknown layer, out-of-range severity |
| `result-too-large` | 413 | Graph over the node cap |
| `purged` | 410 | Deleted under the retention policy |

---

## 6. `POST /v1/scans/{id}/audit`

Runs retrieve → debate → report → retention over a scan whose graph stage has already run.

**Why a POST lives in the read-API ticket:** nothing else in the system creates a report over
HTTP, so `GET /v1/reports/{id}` would have answered "not found" forever however correct it was.
It is the sibling of `POST /v1/scans/{id}/graph`, which exists for the same declared reason —
there is no queue-driven worker yet, so stages are triggered manually.

```json
{ "scan_job_id": "…", "report_id": "a91c…", "report_retained": true,
  "bundle_purged": true, "framing": "draft_audit", "summary": "…",
  "outcome": "Converged", "rounds": 1, "citations": 3 }
```

`report_id` is **null** when the submitter did not opt into retention (SEC-35). That is the
correct answer, not an error: they asked for an audit, not for us to keep one. The audit itself
is still in `summary`.

---

## 7. Tenant scoping

> *"Forgetting tenant scoping on read endpoints. A read leak is still a leak."* — SEC-40

Another tenant's scan answers **404, not 403**. A 403 would confirm the scan exists and that
someone else owns it, which is itself the leak. `ReadApiTenantIsolationTests` probes every
route with a foreign token and asserts the answer is indistinguishable from a scan that was
never created.

Scopes are enforced here for the first time — `AuthScopes.ScanRead` and `ReportRead` existed
as constants before SEC-40 and were checked nowhere. `report:read` is separate from `scan:read`
on purpose: the adjudicated narrative is not the same material as a scan's status.

---

## 8. Verifying it

```bash
dotnet test SentinelAI.slnx --filter "ReadApi|AuditStage"
```

71 tests: 15 tenant isolation, 8 contract, 14 paging/errors, 6 audit stage, 28 list endpoints
(`ListEndpointTests`, which also covers `GET /v1/projects/{id}`, `GET /v1/account` and
`GET /v1/health`).

| Acceptance criterion | Proved by |
|---|---|
| Graph returns nodes + edges with confidence tiers | `The_graph_returns_nodes_and_edges_with_confidence_tiers` |
| Report returns `draft_audit` and per-chain confidence | `The_report_carries_draft_audit_framing_and_per_chain_confidence` |
| Every endpoint tenant-scoped | `ReadApiTenantIsolationTests`, a theory over every route |
| Every endpoint paginated | `Walking_the_cursor_returns_every_finding_exactly_once` — and §3's stated exception for the graph |
| A list never returns another tenant's row | `The_scan_list_never_returns_another_tenants_scan`, which asserts the **absence** of a row in a 200 |
| A summary total equals a walk of the pages | `The_summary_total_matches_a_full_walk_of_the_paged_findings` |

---

## 9. Known gaps

- **The graph is capped, not paged.** A scan over 5,000 nodes gets a `413`. If real repositories
  turn out to exceed that, the answer is a filtered sub-graph query (by layer, or by chain), not
  a page of arbitrary nodes.
- **`corpus_version` on a report is read from the scan job.** If a job is ever re-audited after
  the corpus moves, the report will report the current version rather than the one it was
  reasoned against.
- **Two error formats in one API.** §2. Deliberate and contained; converting the rest is a
  separate change.
- **Chain hops carry `node_key` only when the hop has an edge.** The seed hop arrived from
  nowhere, so its node cannot be derived from an edge that does not exist.
- **No total on the list endpoints.** `GET /v1/scans` and `GET /v1/reports` return a page and a
  cursor, not a count. `GET /v1/scans/{id}/summary` counts one scan's contents; there is no
  equivalent for "how many scans does this tenant have". Add it as a dedicated endpoint if a
  screen needs one — do not infer it by walking pages and calling the result a total.
- **`repo_url` on a list row is the repository's URL *now*.** It is joined from the project, so a
  repository that was renamed shows its current URL against an older scan. That is the right
  answer for a list whose job is recognition; the immutable record of what was scanned is
  `GET /v1/scans/{id}/bundle`.

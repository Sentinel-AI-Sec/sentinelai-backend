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
| GET | `/v1/scans/{id}/bundle` | `scan:read` | — |
| GET | `/v1/scans/{id}/findings` | `scan:read` | ✅ |
| GET | `/v1/scans/{id}/graph` | `scan:read` | — (capped) |
| GET | `/v1/scans/{id}/chains` | `scan:read` | ✅ |
| GET | `/v1/reports/{id}` | `report:read` | — |
| POST | `/v1/scans/{id}/audit` | `scan:write` | — |

The last one is not a read endpoint. See §6.

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

43 tests: 15 tenant isolation, 8 contract, 14 paging/errors, 6 audit stage.

| Acceptance criterion | Proved by |
|---|---|
| Graph returns nodes + edges with confidence tiers | `The_graph_returns_nodes_and_edges_with_confidence_tiers` |
| Report returns `draft_audit` and per-chain confidence | `The_report_carries_draft_audit_framing_and_per_chain_confidence` |
| Every endpoint tenant-scoped | `ReadApiTenantIsolationTests`, a theory over every route |
| Every endpoint paginated | `Walking_the_cursor_returns_every_finding_exactly_once` — and §3's stated exception for the graph |

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

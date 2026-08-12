# The walking skeleton (SEC-45)

One finding, pushed through **every** stage of the backend, where each stage is the thinnest
version that is still honest.

The point is not that any stage is smart. It is that every **seam** — the join where one stage
hands data to the next — exists, fits, and is pinned by a test now. Integration defects are the
expensive kind and they stay hidden until the end if nothing forces the joins to close early.

Source of truth is the code: `src/SentinelAI.Application/Features/Scan/ThinSlice/`.

---

## 1. The pipe

```
findings ──► GraphSeeder ──► IKnowledgeRetriever ──► ScanBriefRenderer ──► IDebateEngine ──► ReportBuilder
   │             │                   │                      │                   │                │
normalize      graph              retrieve                brief              debate           report
(SEC-14/15/16) nodes           knowledge chunks         prompt text        DraftAudit     Report+Citations
```

`ThinSlicePipeline.RunAsync` composes stages 2–5 and returns a `ThinSliceResult` with **one
property per stage**. That is deliberate: a test that can only see the final report cannot tell
a graph that was built and used from one that was silently empty.

Normalization is *not* re-run inside the slice. It is a real stage now with its own pipeline,
and its output is this one's input. Taking findings as a parameter is what keeps that a seam
rather than a merge.

---

## 2. What each stage actually does

| Stage | Type | What it does | What it deliberately does **not** do |
|---|---|---|---|
| Graph | `GraphSeeder` | One `GraphNode` per distinct `NodeRef`; hot at severity ≥ 3 | **No edges.** They come from SEC-17/18 |
| Retrieve | `IKnowledgeRetriever` | One query per linking key, top 5 findings by severity | No ranking — there is no corpus yet |
| Brief | `ScanBriefRenderer` | Renders findings + nodes to prompt text | Never re-spells a node key |
| Debate | `IDebateEngine` | The real SEC-02 engine | — |
| Report | `ReportBuilder` | `Report` + one `Citation` per retrieved chunk | Never cites knowledge nobody fetched |

### Why the graph has no edges

An edge is a claim that two things are related. No scanner reports one — they come from the
Terraform and code readers. A node set with no edges is an honest empty graph; a node set with
guessed edges is a **fabricated chain**, which is the exact failure the Red/Blue debate exists
to reduce. The brief says so in as many words, because an agent handed a node list with no
stated edge policy will infer edges.

### Why `GraphSeeder` throws

A finding whose `NodeRef` is not canonical cannot join the graph, and is therefore invisible to
every stage after it. Skipping it would be silent. So it throws.

It checks `NodeId.IsCanonical`, **not** just `TryParse` — `TryParse` is lenient by design and
lower-cases what it reads, so a hand-built `Code:OrderService` parses happily and then yields
the node key `code:orderservice`, which the finding's own reference no longer matches. That is
the island bug arriving through the front door.

---

## 3. The one remaining stub

`SeedKnowledgeRetriever` answers from a small in-memory map of CWE ids. There is no corpus, no
embedding, no ranking. It exists so the retrieval seam can be crossed before SEC-09 stands up
Qdrant.

It **logs a warning on every call**. A stub retriever that answers quietly looks exactly like a
real one returning thin results, and the failure that causes — a report citing knowledge that
was never retrieved — reads as plausible.

Replacing it is one line in `Infrastructure/DependencyInjection.cs`. Nothing upstream moves.
That property is what the thin slice was built to establish.

---

## 4. The seams, and what breaks if one drifts

| Seam | The contract | Failure if it drifts |
|---|---|---|
| normalize → graph | `Finding.NodeRef` is canonical and **string-equal** to a `GraphNode.NodeKey` | Graph splits into islands. Zero chains found. **Nothing errors.** |
| graph → retrieve | Query is keyed on the finding's CWE/CVE | Retrieval returns unrelated knowledge, confidently |
| retrieve → debate | Node keys appear in the brief verbatim | Agents assert chains whose ids the real graph can never match |
| debate → report | `DraftAudit.Summary` + `Disclaimer` reach `Report.Summary`; `Framing` is `draft_audit` | A draft is presented as a verdict (AID-01 §7) |
| report → citations | One citation per **retrieved** chunk | A report reads as sourced when it is not |

`ReportBuilder.DraftAudit` is a constant, not a parameter. A caller able to pass `"verdict"`
here is the one line of code that would undo AID-01 §7, so there is no such caller.

---

## 5. Tests

| File | Question it answers |
|---|---|
| `WalkingSkeletonTests` | Does each seam hold, in isolation? Scripted debate, one assertion per boundary. |
| `WalkingSkeletonEndToEndTests` | Does the pipe **run**? Real `DebateEngine` over the scripted model provider — offline, deterministic, no credentials. |

`WalkingSkeletonEndToEndTests` also walks a whole bundle: real normalization (SEC-14/15/16) into
the real slice, using the filenames `scripts/run-scanners.sh` writes. That string is where this
project's defects have historically lived, so the test spells it the way the runner does rather
than choosing its own.

Both run offline. A walking-skeleton test that needs a live model is a test nobody runs.

---

## 6. What is still missing

- **A real corpus** — SEC-09. `SeedKnowledgeRetriever` is the placeholder.
- **Persistence** — the slice builds a `Report` and returns it; nothing writes it yet. This is
  also still true of `GraphSeeder`'s own (SEC-16) nodes — only the SEC-17 infra spine
  (`InfraSpineWriter`) actually writes to `GraphNodes`/`GraphEdges` today.
- **The HTTP hop** — `POST /v1/scans` records a bundle but does not yet trigger the slice, and
  nothing yet calls `InfraSpineWriter` from it either — it's a standalone, fully unit-tested
  component (by design, per the SEC-17 ticket) that isn't wired into a live scan job.

### Edges and chaining: what SEC-17/18/19/20 landed

The four seams now build one connected graph, and SEC-20 traverses it into bounded candidate
chains. The fixture's flagship chain reconstructs end to end:

```
pkg:newtonsoft.json --used-by(certain)--> code:orderapp --deployed-as(inferred)-->
task:order_task --assumes(certain)--> iam_role:order_task_role --can-access(certain)-->
s3:customer_data
```

Four hops, `min_confidence = inferred` (the image-name join is the weakest link).
`FlagshipChainTests` runs every real reader, writer, unifier, locator, decorator and traverser
over the fixture's own Terraform and asserts exactly that. Two joins SEC-20 had to add for it to
connect, both documented in `Data_Contracts.md` §2:

- **`code → task` (`deployed-as`).** SEC-19 emitted only `code → image`, which dead-ends: no
  edge left the image node. The task definition is where the code actually runs and what the
  `assumes` edge continues from.
- **`task → role` (`assumes`).** The DOT reversal produces `iam_role → task`, which is the wrong
  way round for this pair. Rather than special-case `AttackDirectionOrienter` — whose regression
  test is the standing guard against the zero-chains bug — the spine reads the role attachment
  from the task definition's own `task_role_arn`. Both edges exist; the ATT&CK tactic ordering in
  traversal discards the backwards one.

**Node-granularity gap: closed by SEC-20.** `FindingUnifier` still keys findings by the finest
subject their scanner reported, and it should; `GraphDecorator` is now the join between that and
the structural nodes, with `IInfraFindingLocator` doing the Terraform line-to-resource half. See
`Data_Contracts.md` §1, "Two granularities, and how they join". Without it there are no hot
seeds and therefore no chains at all, which is why the ticket that needed seeds is the one that
closed it.

### TODOs left open

- **No worker runs the pipeline.** `GraphStagePipeline` now composes the four seam writers plus
  SEC-20 into one callable unit, and `POST /v1/scans/{id}/graph` triggers it by hand — see
  `docs/Testing_With_Postman.md`. That is a manual trigger in the spirit of
  `POST /v1/debates/demo`, not a worker: nothing dequeues the `Queued` job ingest writes, and
  the debate and report stages still have no call site at all.
- **The Dockerfile image label is a local convention.** `DockerfileImageNameExtractor` reads
  `LABEL org.sentinelai.image`, which is not a Docker or OCI standard, and without it the
  code→infra seam has nothing to compare. The label was missing from the committed fixture until
  SEC-20 added it; a real repository has no reason to carry one, so reading the image name from
  the build invocation is the eventual fix.
- **The wildcard-policy → bucket edge is intentionally absent.** Verified against the real
  fixture: `terraform graph` never draws an edge from `aws_iam_role_policy.order_task_policy`
  to `aws_s3_bucket.customer_data`, because the policy's `Resource = "*"` is a literal, not a
  reference. The flagship IAM→S3 reachability has to come from policy-document analysis
  (`Seam.RoleResource`), which is SEC-18's job, not SEC-17's.
- **Several Terraform resource types have no canonical `NodeType` yet** — `aws_security_group`,
  `aws_iam_role_policy`, `aws_s3_bucket_versioning`, `aws_s3_bucket_public_access_block` are
  parsed but dropped as noise at canonicalization (`TerraformResourceTypeMap`). Extending the
  mapping needs a new `NodeType` member first, which is a SEC-03 decision.

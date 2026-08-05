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

- **Edges** — SEC-17/18. Until then no chain is expressible, and the skeleton says so rather
  than inventing one.
- **A real corpus** — SEC-09. `SeedKnowledgeRetriever` is the placeholder.
- **Persistence** — the slice builds a `Report` and returns it; nothing writes it yet.
- **The HTTP hop** — `POST /v1/scans` records a bundle but does not yet trigger the slice.

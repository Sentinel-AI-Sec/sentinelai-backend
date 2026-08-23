# Acceptance demo — run of show (SEC-44)

**The claim:** a full `dep → code → infra → crown-jewel` chain, scanned, graphed, retrieved,
debated, adjudicated, posted and displayed — on a real PR, from real scanner output, across three
layers no single-layer scanner reaches.

**Drivers:** `scripts/demo.sh`, `scripts/demo.ps1`
**Bundle:** `samples/golden-bundle/` — the same one the SEC-49 harness runs on every push

---

## Before you read the script: what counts as the demo

SEC-44's acceptance criterion says **"fixture PR → full three-layer chain … posted, displayed"**.
That means the **GitHub Action** runs: the runner's own scanners produce the SARIF, the collector
gathers the graph inputs, the Action uploads, polls and comments on the PR.

`scripts/demo.sh` drives the same backend flow *without GitHub in front of it*. It is for
rehearsing, for warming a cold start before the room fills, and as the fallback when the live run
fails in front of an audience. **It is not the acceptance criterion**, and a run of it is not
something to claim as the demo.

Both are in the run-of-show below, in that order, and the difference is stated out loud in step 4.

---

## T-minus one week — prerequisites

| Need | Why | Check |
|---|---|---|
| `sentinelai-action` on `dev`, pushed | The delivery leg lives there | `git -C sentinelai-action log --oneline -1` |
| `sentinelai-fixtures` checked out | The fixture PR's repository | `ls sentinelai-fixtures/scan_out` |
| A deployed backend | Or `dotnet run` locally, see below | `curl -i $API/v1/health` → **200** |
| A live model provider | Scripted produces canned turns — real, and unimpressive | `SentinelAI:Models:Provider` |
| A corpus | Or the report's citations come from `SeedKnowledgeRetriever` | `Knowledge:Endpoint` set |
| The UI pointed at the backend | `useDemoData: false`, or `ng serve` with the proxy | |
| A machine token | `POST /v1/auth/login`, or minted from the signing key | |

**Run the fixture-parity checks once, with the fixtures checked out:**

```bash
dotnet test --filter "FullyQualifiedName~FixtureParityTests"
```

They skip on a backend-only checkout. With the fixtures beside you they compare
`samples/golden-bundle/` against the real thing and fail on drift — which is the check that stops
you demonstrating a chain the fixture no longer contains.

---

## T-minus one day — rehearse

**Do the whole thing twice, on the machine and network you will use.** Not once.

```bash
./scripts/demo.sh --api "$API" --token "$TOKEN" --project "$PROJECT_ID"
```

```powershell
.\scripts\demo.ps1 -Api $env:API -Token $env:TOKEN -ProjectId $env:PROJECT_ID
```

Every response lands in `demo-evidence/<timestamp>/`. **Keep the second run's directory** — that
is the backup recording, and step 8 is how you use it.

The driver stops with a named failure if:

- the bundle is missing an entry ingest would refuse (before anything is uploaded);
- no four-hop chain came out of the graph stage — *the three-layer claim did not reconstruct*;
- any stage answered something other than what the next one needs.

**Write down the audit stage's wall-clock time.** It is the only slow step, it varies with the
provider's load, and knowing it is what lets you talk through it rather than watch it.

---

## The run of show

Roughly 12 minutes of demo, plus questions. The timings assume a warmed backend.

### 1. The problem — 90 seconds, no screen

Three scanners, three reports, three silos. OSV says a package is vulnerable. Roslyn says a
method deserializes untrusted input. Checkov says an IAM policy is over-permissive. **Each one is
low or medium severity on its own, and each tool is individually right.** Nobody sees that they
are the same attack path.

Do not open anything yet.

### 2. The fixture PR — 60 seconds

Show the PR. Point at what is in it: a `.tf` change, a `packages.lock.json`, a controller. An
ordinary change nobody would think twice about.

### 3. The Action runs — 2 minutes

The workflow tab, live. What to narrate while it runs:

- the scanners run **on the runner**, and the source never leaves it;
- the collector copies *artifacts* — Terraform, lock files, Dockerfiles, the `terraform graph` DOT
  — and nothing else;
- the upload is the first time anything crosses the network, and it carries findings and
  infrastructure descriptions, not code.

That is the privacy claim, made while the thing that implements it is running.

### 4. If the Action fails — the fallback

Say what you are doing: *"the Action isn't cooperating; this is the same backend flow driven
directly, so you can see the pipeline — the PR comment at the end is the part we'll be skipping."*

```bash
./scripts/demo.sh --api "$API" --token "$TOKEN" --project "$PROJECT_ID"
```

Naming the difference costs five seconds and is the whole difference between a demo and a claim.

### 5. The chain — 3 minutes, the centre of the demo

From the driver's output, or from `GET /v1/scans/{id}/graph`:

```
[Inferred] pkg:newtonsoft.json -> code:orderapp -> task:order_task
           -> iam_role:order_task_role -> s3:customer_data
```

Walk the hops and name what makes each one:

| Hop | Evidence | Confidence |
|---|---|---|
| `pkg → code` | `packages.lock.json` pins the package to the project | Certain |
| `code → infra` | Dockerfile's `org.sentinelai.image` label matches the task's image | **Inferred** |
| `task → role` | The task definition names its own `task_role_arn` | Certain |
| `role → resource` | The inline policy's `s3:*` on `Resource = "*"` | Certain |

**Spend time on the Inferred one.** The image-name join is a convention, not a proof, so the whole
chain inherits it — three certain joins and one inferred makes an inferred chain. That is the
weakest-link rule, and it is what stops this being another tool that reports a guess as a finding.

Then show the distractor: `legacy_worker_task` takes its image from a variable that resolves to no
Dockerfile, so chains through it come back **Unresolved** — *"potential chain, unverified join"*,
recorded rather than dropped and never presented as a result.

### 6. The debate — 2 minutes

While the audit stage runs, explain what is happening: Red asserts the strongest chain, Blue tries
to break each link, the Reporter adjudicates what survived. Both exit paths — convergence and the
turn cap — reach the Reporter, so an audit always comes out.

If tracing is on (SEC-36), **have Langfuse open on a second monitor**: one trace, one span per
turn, tokens and latency per span. It is the most convincing thing in the demo for an audience
that has built with LLMs, because it shows this is not one prompt in a trench coat.

Say the cost figure out loud — it is on the report — and say whether it is priced or only counted.

### 7. The report — 2 minutes

The PR comment: chains first with cited evidence, un-chained findings demoted to a collapsed
count, and the draft-audit framing line.

Then the dashboard, on the same scan. Point at:

- the chain path — **five nodes, starting at the package**;
- the per-hop `blue_verdict`, and that *unassessed* and *unattributed* are not refutations;
- the citations.

Finish on the framing: **this is a draft audit for a human to review, not a verdict.** That line
is in the product for a reason and saying it is not a hedge.

### 8. If something fails live

Open the evidence directory from last night's rehearsal and walk the same JSON. Say that it is a
recording of yesterday's run, and carry on. **An honest recording beats a live failure you talk
over**, and an audience that catches you presenting a recording as live has stopped listening to
anything else.

---

## Failure playbook

| Symptom | Cause | What to do |
|---|---|---|
| First request hangs ~60s | Serverless SQL auto-paused | Warm it 10 minutes before. Run the driver once. |
| `422 … outside the bundle contract` | An entry the layout allowlist refuses | The driver catches this before upload. Check the name — `terraform-graph.dot`, not `terraform.dot`. |
| `503 … outside the egress allowlist` | A configured endpoint is not on the list | Usually the OTLP collector with `CaptureContent` on. Add the host to `Security:Egress:TelemetryHosts`. |
| Audit stage times out | Provider slow or rate-limited | `--timeout 900`. If it is a rate limit, the per-agent keys are the fix. |
| Report has no citations | No corpus configured | `SeedKnowledgeRetriever` is answering. Say so, or set `Knowledge:Endpoint`. |
| Debate converges in one round | Scripted provider | Check `SentinelAI:Models:Provider`. Scripted is the committed default. |
| Chain renders with four nodes | The read API dropped the seed hop | Fixed in `ChainView.HopsOf`. If it reappears, the driver warns; do not present it. |
| Dashboard shows nothing | CORS | `Cors__AllowedOrigins__0` must be the UI's exact origin, no trailing slash. |

---

## Capture checklist

Take these during the rehearsal, not during the demo. Anything you might need to fall back to has
to exist **before** you need it.

- [ ] The fixture PR, before the run
- [ ] The Action workflow, mid-run, with the scanner steps visible
- [ ] The Action's log line showing the bundle upload and its size
- [ ] `POST /v1/scans` → 202 with the poll URL
- [ ] The graph stage response, **the flagship chain path visible in full**
- [ ] The Langfuse trace: one debate, its turn spans, tokens and latency
- [ ] The audit stage response: outcome, rounds, citations, cost
- [ ] The PR comment, chains-first, cited
- [ ] The dashboard's chain view, **five nodes**
- [ ] The dashboard's citation panel
- [ ] A short screen recording of the whole run, unedited, as the step-8 fallback

Keep the whole `demo-evidence/<timestamp>/` directory. The screenshots are for slides; the JSON is
what answers a question you did not expect.

---

## Scope freeze

**No new features from the day the rehearsal starts.** SEC-44's own step 4 says so, and the reason
is in this project's audit history: every blocking defect across five sprints lived in a seam, and
a seam is what a late change moves. The SEC-49 harness runs the whole chain on every push — if it
is green and the fixture-parity checks are green, the demo path is as proven as it gets without
running it.

If something must change during demo week, run the harness before and after, and re-rehearse.

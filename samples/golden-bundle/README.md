# The golden bundle

The reference fixture's three-layer chain, as the files a scan bundle carries.

**Two things read this directory, and that is the point:**

| Reader | What it does |
|---|---|
| `tests/SentinelAI.Integration.Tests/Regression/` (SEC-49) | Packs it into a `.tar.gz` and runs the whole pipeline over it on every push |
| `scripts/demo.sh` (SEC-44) | Packs the same files and uploads them to a deployed backend |

So the acceptance demo runs over exactly the bytes CI proves. A rehearsal that used its own
inputs would be demonstrating something no test has ever run.

## The chain

```
pkg:newtonsoft.json  --used-by-->  code:orderapp  --deployed-as-->
    task:order_task  --assumes-->  iam_role:order_task_role  --can-access-->  s3:customer_data
```

Four hops, crossing every layer the product claims to reason across. Each one is a join a
single-layer scanner cannot make:

- **dep→code** — `packages.lock.json` names the vulnerable package and the project.
- **code→infra** — the Dockerfile's `LABEL org.sentinelai.image` matches `main.tf`'s container
  image coordinate. This is the join that is a *convention*, not a proof, so the whole chain
  inherits `Inferred` confidence however certain the other three are.
- **task→role** — the task definition names its own `task_role_arn`.
- **role→resource** — the inline policy's `s3:*` on `Resource = "*"` reaches the bucket.

Plus one deliberate distractor: `legacy.tf`'s `legacy_worker_task` takes its image from a
variable resolving to no Dockerfile here, so any chain through it is `Unresolved` — "potential
chain, unverified join", never a confirmed result.

## Load-bearing details

Do not tidy these.

**`iam.tf` line 25 is the `aws_iam_role_policy` block.** `findings/checkov.sarif` reports the
flagship finding at `infra/iam.tf:25`, and `TerraformFindingLocator` joins a scanner's
`file:line` to the block containing it. Removing a comment line moves the block, the finding
stops landing on the role, and the chain loses its seed — with no error, just one fewer
candidate.

**`legacy.tf` writes `image = var.legacy_worker_image` bare, not `"${var.legacy_worker_image}"`.**
That single pair of quotes is finding 19-B: a copy that had them matched a regex the real
extractor did not, so the fixture's legacy task was dropped from the extractor's output
entirely — not recorded as unresolved, simply gone. The tier the distractor exists to prove was
unreachable in production for a sprint, and the quotes are why nobody could see it.

**The Dockerfile carries `LABEL org.sentinelai.image`.** For one sprint a copy of this file had
that label and the real fixture did not, so `FlagshipChainTests` asserted the flagship chain end
to end and passed while the committed fixture produced seven two-node candidates and no flagship.

**`findings/osv.sarif`, not `osv.json`.** The runner writes SARIF. Routing only `.json` dropped
an entire scanner's output, silently, and the scan looked clean.

**`graph-inputs/terraform-graph.dot`, exactly that name.** The bundle layout allowlist
(`BundleContentPolicy`) names it; `terraform.dot` is refused with 422.

## Where `metadata.json` is

Generated per run, not committed — it carries the project id and commit sha of whatever run is
happening. `GoldenBundle.MetadataJson` and `scripts/demo.sh` build the same shape.

## Parity with the real fixture

These files are the fixture *trimmed to the blocks that carry the chain*.
`FixtureParityTests` checks that every meaningful line here still appears in
`sentinelai-fixtures`, whenever that repository is checked out beside this one — and skips with a
stated reason when it is not.

To activate it, clone the fixtures as a sibling:

```
workspace/
  sentinelai-backend/     ← you are here
  sentinelai-fixtures/
```

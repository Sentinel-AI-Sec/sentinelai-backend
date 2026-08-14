# Sandboxed backend processing (SEC-34)

What the backend actually enforces about *where a job's content can go* and *what a job is
allowed to contain*, and — just as important — what it does not enforce.

Source of truth is the code. This page is a map of it, and a boundary marker: **do not read
the word "sandbox" here as an OS-level or network-level sandbox. There isn't one.**

---

## 1. The honest summary

| SEC-34 step | Status | Where |
|---|---|---|
| 1. Ephemeral per-job context | ⚠️ **partial, pre-existing** | per-request DI scope; bundle bytes in a job-scoped directory |
| 1. Egress restricted to LLM/RAG endpoints | 🟡 **policy-level only** | `EgressPolicy` + `EgressAdmission`, checked at ingest |
| 2. Artifacts never used to train a model | 🟡 **partly mechanical, partly contractual** | `EgressPolicy.DeniedPathSegments`; the rest is vendor terms |
| 3. No application source to process | ✅ **enforced and falsifiable** | `BundleContentPolicy`, called by `SubmitScanCommandHandler` |
| 4. Tear down the context after the job | ⚠️ **pre-existing, manual** | `PurgeScanBundleCommand` (SEC-29), `POST /v1/scans/{id}/purge` |

Only row 3 is a guarantee. Rows 1 and 4 describe what already existed before this ticket.
Row 2 is half a mechanism and half a contract. Row 1's egress half is a configuration
assertion — read section 3 before repeating any claim about it.

---

## 2. No application source to process — the part that is real

**The property.** A received bundle contains `metadata.json`, `scanner-versions.json`, the
scanners' output under `findings/`, and the graph inputs the runner's collector copies under
`graph-inputs/`. Nothing else. There is therefore no application source in the backend for
any stage to read, embed, or put in a prompt.

**Why the backend asserts it when three other guards already claim it.** The claim was true
and unverified by anything we run:

- `collect-graph-inputs.sh` is a whitelist and says so in its own header — but it runs on the
  customer's machine.
- `assert-no-source.sh` runs twice on the runner — same machine, same caveat, and its tarball
  pass has been reported as vacuous by five consecutive sprint audits (it passes when nothing
  was built).
- `TarGzBundleInspector` applies an extension denylist on ingest — ours, but a denylist.

Four claims, no test on our infrastructure that demonstrates a rejection of a realistic
bundle. A property that holds by construction elsewhere is not a property we verified.

**Why an allowlist, not another denylist.** The existing denylist is the argument. Its
pattern spells out `ts`, `tsx` and `jsx` and omits `js` — so an entire Node application can be
uploaded and every guard in the chain reports a pass. `sql`, `sh` and `ps1` are missing too.
Any denylist has that shape: it is a list of the languages someone thought of. The bundle
contract is short and known, so `BundleContentPolicy` allows exactly it and refuses
everything else, including files nobody has a name for yet.

**What it is allowed to contain**, mirroring `collect-graph-inputs.sh` pattern for pattern:

```
metadata.json
scanner-versions.json
findings/*.sarif  findings/*.json
graph-inputs/**/terraform-graph.dot
graph-inputs/**/*.tf          graph-inputs/**/*.tf.json
graph-inputs/**/Dockerfile    graph-inputs/**/Dockerfile.*
graph-inputs/**/*.csproj
graph-inputs/**/packages.lock.json
graph-inputs/**/package-lock.json
```

That coupling is deliberate and fails closed: if the collector grows a pattern and this list
does not, real bundles start being refused rather than quietly accepted.

**Two different rejections.** A `.cs` file means the Action's guard did not run — a defect
worth chasing. A stray `README.md` means the contract drifted. The decision reports them
separately so the message and the log level can say which happened.

**What it does not check.** Names only. A `.tf` whose body is C# passes. A
`findings/*.sarif` whose `snippet` fields quote the customer's source passes — SARIF
legitimately carries code excerpts, and refusing those would refuse every real Roslyn report.
Content-level protection for what reaches a model is [ingress redaction](Ingress_Redaction.md)
(SEC-33), not this.

**Proven by** — every one of these is a rejection, not an acceptance:

| Test | What it proves |
|---|---|
| `BundleContentPolicyTests.A_cs_file_is_rejected_and_reported_as_application_source` | the assertion fails on a `.cs` file |
| `BundleContentPolicyTests.Source_extensions_the_upstream_denylist_omits_are_still_rejected` | `.js`, `.mjs`, `.sh`, `.sql`, `.ps1` — the gap the denylist has |
| `BundleContentPolicyTests.Source_hidden_under_graph_inputs_is_still_source` | a check scoped to "outside `graph-inputs/`" would miss this |
| `BundleContentPolicyTests.A_file_that_is_not_source_but_is_not_in_the_contract_is_still_refused` | "bundle only" means *only* |
| `SandboxedProcessingTests.A_bundle_the_ingest_denylist_waves_through_is_still_refused` | asserts the inspector **accepts** the `.js` bundle first, then that the handler refuses it — the assertion is load-bearing, not a second opinion |

---

## 3. Restricted egress — read this before repeating the claim

**What exists.** `EgressPolicy` is an allowlist of hosts, split by purpose (LLM inference,
RAG retrieval). `EgressAdmission` compares it against every endpoint this process has been
*configured* to call, and `SubmitScanCommandHandler` calls that on the ingest path: a
deployment configured to send job content off the allowlist **stops accepting scan jobs**,
with `503` and the offending host named.

**What does not exist.** Interception of an outbound call. There is no proxy, no
`DelegatingHandler`, no network namespace, no egress firewall. The model clients are built on
`System.ClientModel`'s pipeline inside `ChatClientFactory`, and nothing in this repository
inspects the requests they make. If configuration passes the check and some other code
constructs a client by hand, or a library phones home, **nothing here stops it.**

So the enforceable statement is narrower than the acceptance criterion, and it is this:

> A scan job is never accepted into a process whose outbound *configuration* points at a host
> that is not on the allowlist.

Real egress restriction is a network namespace, an egress firewall, or a deny-by-default
sidecar — infrastructure, configured outside this repository. None of it is deployed. Anyone
writing "egress is restricted" in a demo script should write "egress is *policy-restricted at
ingest*" instead.

**Why the allowlist is compiled in.** The obvious implementation — derive the allowlist from
the endpoints the app is configured to call — produces an assertion that cannot fail. The
list is fixed to the vendors the provider abstraction can speak to:

| Host | Purpose |
|---|---|
| `api.openai.com` | LLM |
| `*.openai.azure.com` | LLM (host carries the customer's resource name) |
| `api.anthropic.com` | LLM |
| `integrate.api.nvidia.com` | LLM |

`Scripted`, the default provider, is offline and configures no endpoint at all, so a default
deployment has an empty catalog and passes trivially. That is correct, and it is stated as
its own test so a passing result is distinguishable from a check that passes unconditionally.

**Adding a host.** `Security:Egress:LlmHosts` and `Security:Egress:RagHosts` accept exact
hosts or a `*.suffix` wildcard:

```jsonc
"Security": {
  "Egress": {
    "LlmHosts": ["llm-gateway.internal.example"],
    "RagHosts": ["qdrant.internal.example"]     // SEC-09's vector store, when it exists
  }
}
```

Additions only. **There is no configuration key that removes a vendor default or turns the
check off** — a kill switch is the first thing reached for at 2am, and a guard the
misconfigured file can disable is not a guard.

**Also refused:** plaintext `http` to an allowed host (the prompt in the clear on someone's
network; loopback is exempt so a local vector store is usable), and a value that does not
parse as an absolute URI — a typo must not become an empty catalog and a clean pass.

**Proven by** `EgressPolicyTests` and the two paired cases in `SandboxedProcessingTests`:
`A_job_is_refused_while_the_deployment_points_off_the_allowlist` and
`The_same_job_is_accepted_when_the_endpoint_is_an_allowed_provider`. The pair matters —
without the second, the first would pass against a check that refused everything.

---

## 4. Never used to train a model

This promise has two halves and only one of them is code.

**The half we own is mechanical.** The only destinations on the allowlist are inference and
retrieval. There is no analytics, telemetry, or dataset host among them, and
`EgressPolicy.DeniedPathSegments` refuses the fine-tuning, dataset and bulk-upload routes
(`/fine_tuning`, `/training`, `/datasets`, `/uploads`, …) **even on a host that is otherwise
allowed**. A customer artifact cannot be submitted for training through a route this policy
permits.

**The half we do not own is contractual.** Whether a vendor trains on data sent to its
inference endpoint is settled by the account's terms — zero-retention agreements, enterprise
tiers — and no code of ours can verify it. Do not claim otherwise. The deployment checklist
item is real and belongs to whoever signs the vendor contract.

---

## 5. Ephemeral context and teardown

Both steps predate this ticket and neither is a sandbox.

- **Per-job isolation** is the ASP.NET request scope plus a job-scoped bundle directory
  (`BundleStorage:RootPath`, `FileSystemBundleStore`). Two jobs do not share state, but they
  do share a process, a filesystem, and a network namespace.
- **Teardown** is `POST /v1/scans/{id}/purge` (SEC-29), which deletes the stored bundle and
  sets `scan_jobs.bundle_purged`. It is idempotent, and it is **manual** — nothing calls it
  automatically at the end of a job, because there is no queue-driven worker to call it from.

A genuinely ephemeral context — a container or microVM per job, torn down with the job — is
infrastructure work and is not started.

---

## 6. Where the code is

| Piece | File |
|---|---|
| Bundle layout allowlist | `src/SentinelAI.Application/Features/Scan/Security/BundleContentPolicy.cs` |
| Egress allowlist + rules | `src/SentinelAI.Application/Features/Scan/Security/EgressPolicy.cs` |
| The configured-endpoint port | `src/SentinelAI.Application/Features/Scan/Security/IOutboundEndpointCatalog.cs` |
| The admission decision | `src/SentinelAI.Application/Features/Scan/Security/EgressAdmission.cs` |
| Config binding for the allowlist | `src/SentinelAI.Infrastructure/Security/EgressOptions.cs` |
| Reading the configured endpoints | `src/SentinelAI.Infrastructure/Security/ConfiguredOutboundEndpoints.cs` |
| Both checks on the ingest path | `src/SentinelAI.Application/Features/Scan/Commands/Submit/SubmitScanCommandHandler.cs` |

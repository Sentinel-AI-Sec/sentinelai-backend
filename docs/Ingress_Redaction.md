# Ingress secret scan & redaction (SEC-33)

The backend's guarantee that no customer credential reaches a model. A bundle arrives, and
before anything persists it, renders it into a prompt, or sends it anywhere, every piece of
text it contributed is scanned; credentials are removed, the removal is recorded, and each
one found is reported back to the customer as a high-severity finding.

Source of truth is the code. This page is a map of it.

---

## 1. Why it's shaped this way

**A leaked secret cannot be recalled.** Everything else in this system is recoverable — a
bad graph is rebuilt, a wrong chain is re-adjudicated, a failed scan is re-run. A credential
sent to a third-party model provider is in someone else's logs, permanently, and no amount
of fixing our code afterwards changes that. So this is the one stage designed around
"cannot be undone" rather than "can be corrected".

**The runner's pre-scan cannot be the guarantee.** The Action runs Gitleaks on the
customer's machine, under the customer's configuration, and reports its own result. It can
be skipped, misconfigured, pinned to a stale rule set, or simply report `passed` having
never run — and the bundle records that honestly: `scan_bundles.runner_secret_scan` stores
`skipped` as faithfully as `passed`. This gate is what makes the promise hold in every one
of those cases, so **it never reads that field to decide whether to run.** A backstop with a
condition on it is not a backstop.

**Redaction alone helps us, not the customer.** Removing a key from a prompt protects our
data path. The key is still in their repository. Reporting it at severity 4 is the half of
this work that is worth something to them — and it is exactly where the toolchain is
weakest: the fixture records that Security Code Scan has no hardcoded-secret rule at all,
so CODE-04 and CODE-05 go unreported by every scanner in the bundle.

**False positives are cheap; false negatives are not.** A false positive costs a redacted
word in a prompt. A false negative costs a live credential in a third party's logs. Every
rule is tuned for that asymmetry: ambiguous values are redacted.

---

## 2. Where it runs

```
POST /v1/scans/{id}/graph
  └─ RunGraphStageCommandHandler
       1. NormalizationPipeline      SARIF/JSON  → findings          (SEC-14/15/16)
       2. IngressRedactionGate       ← the gate                       (SEC-33)
       3. MarkRedactionAppliedAsync  → scan_bundles.ingress_redaction_applied
       4. NormalizedFindingWriter    findings    → rows
       5. GraphStagePipeline         graph, chains                    (SEC-17…20)
```

Step 2 is the earliest point at which scanner text exists as findings, and the latest point
before anything is written down or sent on. The normalizer's list is deliberately not used
again after it: the gate's output is what continues.

**A second guard sits at the model call itself.** `RedactingDebateEngine` decorates
`IDebateEngine`, so the last thing between any brief and a provider is a secret scan. In the
normal flow it finds nothing, and that is the point — the acceptance criterion is "no secret
reaches the model", and the only place that can be *enforced* rather than argued is the
boundary. Two live paths already bypass the gate and are covered only by this: `POST
/v1/debates` takes a brief as free text from the caller, and `ScanBriefRenderer` folds in
retrieved knowledge chunks that never passed through ingest.

Nothing resolves the bare engine. `IDebateEngine` *is* the wrapper, decided at registration,
because a guard you have to opt into is a guard someone eventually forgets.

---

## 3. File-by-file

### Domain (ports + contracts)

| File | What it is |
|---|---|
| `Abstractions/ISecretScanner.cs` | The port: one method, text in, redacted text plus matches out. |
| `Abstractions/ScannerNames.cs` | `IngressGate = "ingress-gate"` — the provenance stamp on findings we raised ourselves. |

**`SecretMatch` deliberately has no value field.** A scanner that handed back the plaintext
it found would be one enthusiastic log line away from writing every customer credential into
our own telemetry — the exact failure this ticket exists to prevent, reintroduced by the
component meant to prevent it. Detection and redaction are also a single call for a related
reason: a caller cannot detect and then forget to redact.

### Application (`Features/Scan/Security/`)

| File | What it does |
|---|---|
| `IngressRedactionGate.cs` | The stage. Redacts finding messages, scans artifacts, raises secret findings. |
| `IngressRedactionResult.cs` | Counts only — nothing in it can carry a credential, so downstream logging is safe by construction. |
| `RedactingDebateEngine.cs` | The decorator at the model boundary. |

### Infrastructure (`Security/`)

| File | What it does |
|---|---|
| `RegexSecretScanner.cs` | The rules. Singleton and stateless; retains nothing between calls. |

### Tests

| File | Covers |
|---|---|
| `Infrastructure.Tests/Security/RegexSecretScannerTests.cs` | Detection, placeholders, line numbers, overlap. |
| `Infrastructure.Tests/Security/IngressRedactionGateTests.cs` | The three acceptance criteria and the degraded paths. |
| `Infrastructure.Tests/Security/RedactingDebateEngineTests.cs` | The boundary guard. |
| `Integration.Tests/Scan/RunGraphStageCommandHandlerTests.cs` | The flag and the finding, through the real handler. |

---

## 4. The rules

Two families, and the split is what keeps the noise down.

**Shaped** — the credential announces itself, so the shape alone is near-conclusive:
`private-key` (PEM blocks), `aws-access-key-id`, `github-token`, `slack-token`,
`google-api-key`, `jwt`, `url-embedded-password`.

**Assignment** — the value is only a secret because of the word beside it:
`aws-secret-access-key`, `connection-string-password`, `bearer-token`, `assigned-secret`
(`api_key = "…"`, `ENV APP_KEY="…"`), and `terraform-variable-default`.

That last one earns its place. `variable "db_password" { default = "…" }` is the single most
common way a credential ends up committed in Terraform — a variable declared for the right
reason and then given a working value "temporarily" — and no assignment rule can see it: the
keyword is in the block header, and the value sits beside the neutral word `default`.

**Placeholders are excluded, and this is load-bearing.** `password = var.db_password` and
`= "${var.db_password}"` appear in nearly every real `.tf` file and are evidence the author
did the right thing. Without the exclusion, every bundle would arrive carrying dozens of
"hardcoded secret" findings that are the opposite of findings — and a gate whose output is
mostly noise gets ignored, which is a security failure with extra steps.

**A scan timeout fails closed.** Each pattern carries a 2-second cap, and a timeout redacts
the whole text rather than forwarding content we could not finish checking.

---

## 5. What gets written

| Column | Set to | Meaning |
|---|---|---|
| `scan_bundles.ingress_redaction_applied` | `true` once the gate completes | The check happened. |
| `findings.redacted` | `true` on each finding whose message changed | This text was cleaned before anything saw it. |

**The bundle flag records that the gate ran, not that it found something.** A clean bundle
and an unchecked bundle are different facts, and `false` has to keep meaning "nobody
looked" — otherwise the column proves nothing, which defeats the reason it exists. It is
written before the graph stage, so a job that dies in traversal still carries the truth
about what was scanned.

`Finding.Redacted` is also `true` on the secret findings the gate raises, which were never
redacted — they were *written* redacted. Same claim: no unredacted form of that text ever
existed.

### The finding raised for a hardcoded secret

```
source_tool  ingress-gate
layer        infra
severity     4                     (top of the 0–4 contract scale)
cwe_id       CWE-798               (the only CWE this gate ever assigns)
check_id     <rule id>             e.g. assigned-secret
location     Dockerfile:3          repo-relative, the file the developer has to open
node_ref     resource:dockerfile   via FindingUnifier.NodeRefFor — never spelled by hand
redacted     true
```

The node reference comes from `FindingUnifier.NodeRefFor` rather than being built here, so
the finding lands on the same node as every other finding about that file. Spelling a key by
hand is the exact mechanism SEC-03 exists to prevent, and the consequence would be quiet: a
secret finding on an island node, decorating nothing, seeding no chain.

**One finding per (file, line, rule).** A key repeated on twenty lines is twenty things to
rotate; the same key matched twice by two overlapping rules is one thing. Overlapping
redactions are merged rather than nested for the same reason — `[REDACTED:[REDACTED:jwt]…]`
is both unreadable and a false count.

---

## 6. What happens when things go wrong

| Situation | Behaviour | Why |
|---|---|---|
| Bundle unreadable | Finding text is still redacted; artifacts are skipped, logged at warning | The graph stage fails loudly on the same bundle a moment later; that is where the diagnosis belongs. A redaction step that turned a degraded scan into no scan would get switched off. |
| An artifact is not text | Undecodable bytes become replacement characters; the file reports nothing, the rest are still scanned | One binary in a bundle must not stop the gate. |
| A rule times out | The whole text is redacted | Fail closed. |
| A secret reaches the model boundary | Redacted there, logged at **warning**, debate still runs | The redaction is the mitigation; stopping the scan is not. The warning says an upstream path is not redacting. |

---

## 7. Known limits

- **Detection is pattern-based, so it is not complete.** A high-entropy value with no
  keyword beside it and no issuer-specific shape — a bare base64 blob in a config file —
  will not be caught. Entropy scoring would widen coverage at a real false-positive cost;
  it was not worth it for this sprint, and the boundary guard limits the blast radius.
- **Only bundle artifacts and finding text are scanned.** Retrieved knowledge chunks reach
  a prompt through `ScanBriefRenderer` without passing the gate; they are covered by
  `RedactingDebateEngine` alone. That is adequate — it is the boundary — but it means a
  secret in the corpus is caught late and logged as an upstream fault rather than prevented.
- **`POST /v1/debates` is not authenticated as a scan path.** It takes free text and is
  covered only by the boundary guard.

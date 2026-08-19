# Retention, encryption & purge (SEC-35)

"We delete your data" was a claim with no mechanism behind it. Every field the promise needed
already existed — and nothing set any of them. This task makes the promise true.

Source of truth is the code. This page is a map of it.

---

## 1. What was wrong

The scaffolding was all present, which is what made it dangerous: the system read as though
retention worked.

| Field | Before this task |
|---|---|
| `ScanJob.BundlePurged` | Only ever set by the manual `DELETE /v1/scans/{id}` endpoint. A bundle nobody remembered to purge stayed on disk forever. |
| `ScanJob.RetainReport` | Read from `metadata.retain_report` at ingest, stored, and **never looked at again**. |
| `Report.Retained` | Hardcoded `false` by `ReportBuilder`, and nothing acted on it. |
| Account deletion | Did not exist. |
| HTTPS | Not enforced anywhere in the pipeline. |

The sharpest of these: a submitter could say "don't keep my report", the system would record
their choice in a field called `RetainReport`, and then ignore it. **A promise with a flag and
no behaviour is worse than no promise, because it reads as kept.**

---

## 2. The two rules, and where they run

```
ThinSlicePipeline.RunAsync
  │
  ├─ Stage 2  graph
  ├─ Stage 3  retrieve
  ├─ Stage 4  debate
  ├─ Stage 5  report        ReportBuilder → Report (Retained = false, it cannot know)
  │
  ▼
  Stage 6  retention        IScanRetentionPolicy            ← SEC-35
     │
     ├─ Rule 1: bundleStore.PurgeAsync(jobId)   always. job.BundlePurged = true
     └─ Rule 2: report.Retained = job.RetainReport
                  retained  → persist the report
                  not       → never written, and any earlier stored report is removed
```

Retention is a **stage of the pipeline**, not a follow-up call. That is the whole point: making
it a step is what stops "we delete your data" from depending on an operator remembering to
invoke an endpoint.

### Ordering that matters

The bundle is deleted from storage **before** the row is flagged. Reversed, a failed save would
leave the database claiming a purge that never happened — and the flag is what stops a retry, so
nothing would ever try again. Purging first can at worst delete the bundle and fail to record
it, which the next call simply repeats: `IBundleStore.PurgeAsync` is idempotent by contract.

---

## 3. Account deletion

`DELETE /v1/account` removes everything belonging to the caller's tenant: projects, scan jobs,
stored bundles, findings, the resource graph, chains, reports and users.

**It takes no id.** A caller can only delete their own account, so there is no request that
could name someone else's tenant — an entire class of authorization bug removed from the most
destructive operation in the system by not having a parameter.

**It is irreversible.** Nothing is soft-deleted. A grace period would mean still holding data
we said we destroyed.

### Why the delete order is the hard part

Most foreign keys in this schema cascade, but `ChainHop → Finding / Chain / GraphNode` and
`GraphEdge → GraphNode` are `Restrict` — deliberately, since a chain hop pointing at a finding
that silently vanished is a corrupted audit trail. Deleting in the obvious order (jobs first,
let the cascades run) throws a foreign-key violation partway through and leaves the account
**half deleted**. For a feature whose entire purpose is "your data is gone", partial success is
the worst possible outcome.

So `TenantPurgeService` deletes children before parents, explicitly, inside a transaction:

```
Citation → ChainHop → GraphEdge → Chain → Report → Finding → GraphNode
        → ScanBundle → ScanJob → Project → RefreshToken → User → Tenant
```

Stored bundles are purged **before** the rows, while the job rows still say which bundles
exist. After `ScanJob` is deleted there is nothing left pointing at those files — they would be
orphaned on disk, deleted from the record and undeletable forever.

---

## 4. Encryption

This is the part where the honest answer is not "done".

| | Status |
|---|---|
| **In transit — client → API** | **Enforced.** `Security:RequireHttps` adds HSTS + HTTPS redirection, on by default outside Development. |
| **In transit — API → database** | **Configurable, and it matters here.** See below. |
| **At rest — the database itself** | **Not available on the current host.** See §4.1. |
| **Secrets** | Environment variables / the hosting control panel. Azure Key Vault does not apply — this is not deployed on Azure. |

`Security:HttpsPort` is set explicitly (default 443) because `UseHttpsRedirection` does nothing
at all when it cannot determine a port — it logs a warning and passes the request through in
the clear. Behind a proxy that terminates TLS there is no port to detect, so leaving it unset
means transport security *appears* configured and silently is not. That was a real bug found
while testing this, not a hypothetical.

### 4.1 Encryption at rest, on shared hosting

The database is deployed on **SmarterASP.NET shared hosting**. Transparent Data Encryption
needs `sysadmin` and a certificate in `master`; shared hosting grants neither. Verify for
yourself:

```sql
SELECT SERVERPROPERTY('Edition') AS Edition, SERVERPROPERTY('EngineEdition') AS EngineEdition;
```

**The decision taken was to document this rather than fake it.** Application-level column
encryption was considered and rejected: the unlock key would sit on the same host as the data
it protects, which limits what it actually buys, and the encrypted columns stop being
searchable.

What that leaves is a coherent position rather than a missing checkbox:

> We cannot encrypt at rest on this host, so we minimise what is at rest. Bundles are deleted
> immediately after the audit, reports are kept only on explicit opt-in, and account deletion
> removes everything. **Data that is gone cannot leak from an unencrypted disk.**

Retention is therefore the *primary* data-protection control here, not a secondary one.

Two things are already protected independently of the database, and TDE would add nothing to
either: `User.PasswordHash` and `RefreshToken.TokenHash` are both hashed, and refresh tokens
rotate on every use.

### 4.2 The connection string

Against a **remote** server the connection crosses the public internet, so it must carry
`Encrypt=True`. Note that `TrustServerCertificate=True` — harmless for LocalDB over a loopback
socket — encrypts *without checking who answered* on a remote host, which throws away most of
the protection. Drop it if the server presents a valid certificate.

---

## 5. File-by-file

### Application

| File | |
|---|---|
| `Abstractions/IScanRetentionPolicy.cs` | **New.** The policy port + `RetentionOutcome`. |
| `Features/Scan/Retention/ScanRetentionPolicy.cs` | **New.** The two rules. |
| `Features/Account/Commands/Delete/*` | **New.** `DeleteAccountCommand` + handler + response. |
| `Features/Scan/ThinSlice/ThinSlicePipeline.cs` | Retention added as stage 6. |
| `Features/Scan/ThinSlice/ThinSliceResult.cs` | Carries the `Retention` outcome. |

### Infrastructure / Domain / Api

| File | |
|---|---|
| `Domain/Abstractions/Repositories/ITenantPurge.cs` | **New.** Port + `TenantPurgeReport`. |
| `Infrastructure/.../TenantPurgeService.cs` | **New.** The ordered cascade. |
| `Api/Controllers/AccountController.cs` | **New.** `DELETE /v1/account`. |
| `Api/DependencyInjection.cs` | HSTS, HTTPS redirection, explicit HTTPS port. |

### Tests — 24 new

| File | | |
|---|---|---|
| `Retention/AccountDeletionTests.cs` | 6 | The ordered cascade, **on SQLite** |
| `Retention/AccountDeletionEndpointTests.cs` | 7 | The endpoint's authorization boundary |
| `Retention/ScanRetentionTests.cs` | 8 | The two rules |
| `Retention/TransportSecurityTests.cs` | 3 | The HTTPS redirect |

---

## 6. Why the deletion tests run on SQLite

Every other integration test here uses EF's in-memory provider. The account-deletion tests do
not, and that choice is load-bearing.

**The in-memory provider does not enforce foreign keys at all.** The delete order in §3 exists
solely to satisfy `Restrict` keys — so tested in memory, a wrong order passes every assertion
and then throws the first time it meets a real database, leaving an account half deleted. The
tests would have been green and worthless.

This was verified rather than assumed: with the delete order deliberately broken, 4 of the 6
tests fail with SQLite foreign-key violations. Restored, all 6 pass.

### The guard that outlives this sprint

`Deleting_an_account_removes_every_row_it_owned` does not check a hand-written list of tables.
It reflects over the EF model, finds every `ITenantOwned` entity, and asserts each is empty.

A hand-written list is correct the day it is written and silently wrong the day someone adds a
table and forgets this method — and a table that survives account deletion **forever** is
exactly the failure this feature exists to prevent. With the reflection guard, a new entity
that the purge does not cover fails the test with a message naming it.

---

## 7. Verifying it

```bash
dotnet test SentinelAI.slnx --filter "Retention|AccountDeletion|TransportSecurity"
```

Then the whole suite:

```bash
dotnet test SentinelAI.slnx
```

### Acceptance criteria

| The task asks | Where it is proved |
|---|---|
| Bundle purged after the audit by default (`BundlePurged` set) | `ScanRetentionTests.The_bundle_is_deleted_and_the_job_records_it` — asserts both the store call *and* the flag |
| Reports kept only if opted in | `A_report_nobody_opted_into_is_never_written_down` / `A_report_the_submitter_asked_for_is_kept`, plus `Withdrawing_consent_removes_a_report_stored_by_an_earlier_run` |
| Account deletion purges all associated data | `Deleting_an_account_removes_every_row_it_owned` (reflection over the whole model) + `Stored_bundles_are_purged_from_storage_not_only_from_the_database` |
| Data encrypted in transit and at rest | In transit: `TransportSecurityTests`. At rest: **not achievable on this host** — §4.1 |

---

## 8. Known gaps

- **Encryption at rest is not implemented.** §4.1 explains why and what is done instead. This
  is the one acceptance criterion not met, and it is a hosting limitation, not an omission.
- **Retention fires where the pipeline ends today.** `ThinSlicePipeline` is the only end-to-end
  path, so retention is stage 6 of it. There is still no queue-driven worker; when one is built
  it **must** run the pipeline rather than re-implement the stages, or bundles stop being
  deleted and nothing will report an error. That is the residual risk in this task.
- **No retention period for opted-in reports.** A report the submitter asked us to keep is kept
  indefinitely. "Keep for 90 days" would need a scheduled job, which nothing here provides.
- **Deletion is not audited anywhere durable.** The account purge is logged at warning level,
  but after it completes no row anywhere records that the account existed — by design, and it
  means the log is the only trace.

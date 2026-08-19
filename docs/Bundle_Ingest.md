# Bundle ingest & provenance (SEC-13)

The backend's front door. A GitHub Action packages scan artifacts into a `.tar.gz`,
uploads it to `POST /v1/scans`, and this endpoint accepts it, refuses anything carrying
application source, records where it came from, and returns immediately — the actual
scan pipeline runs afterward, out of the request.

Source of truth is the code. This page is a map of it.

---

## 1. Why it's shaped this way

Three constraints drive every design decision here:

1. **"Your code never leaves your runner" is a privacy promise, not a suggestion.** The
   Action already strips source before upload (twice — `scripts/assert-no-source.sh` runs
   in the runner). This endpoint is the third check, and the only one on infrastructure
   SentinelAI controls. If the first two ever fail, this one still has to catch it, because
   this is the party that would be embarrassed if it didn't.
2. **Scanning takes time; the HTTP request can't wait for it.** A web request that blocks
   for 90 seconds times out. So ingest does the minimum needed to accept-or-reject a
   bundle, writes provenance, and returns `202 Accepted` with a poll URL. Nothing in this
   endpoint parses SARIF, builds a graph, or runs a debate — that's a separate worker,
   triggered by the `Queued` row this endpoint writes.
3. **Provenance has to describe exactly what arrived, not what the caller claims arrived.**
   The bundle is hashed before it's interpreted, and the runner's own manifest
   (`metadata.json`'s `artifacts` list) is cross-checked against what the tarball actually
   contains. A mismatch is refused, not silently recorded.

---

## 2. Request flow

```
POST /v1/scans   (multipart/form-data: "metadata" text part + "bundle" file part)
  │
  ▼
ScanController.Submit                              [SentinelAI.Api]
  - [Authorize] gate: JWT bearer required
  - reads the two multipart parts, opens the bundle as a Stream
  - sends SubmitScanCommand via MediatR
  │
  ▼
ValidationBehavior<SubmitScanCommand, Response>     [SentinelAI.Application]
  - runs SubmitScanCommandValidator (both multipart parts present?)
  - short-circuits to a 400 Response if not — the handler never runs
  │
  ▼
SubmitScanCommandHandler.Handle                     [SentinelAI.Application]
  1. Authorize      — caller.IsAuthenticated, caller.HasScope("scan:write")
  2. Parse metadata — deserialize metadata.json, validate project_id/commit_sha/tier hint
  3. Resolve project — tenant-scoped lookup; wrong tenant looks identical to "not found"
  4. Inspect bundle — TarGzBundleInspector: hash, enumerate entries, refuse source,
                       cross-check the manifest against what's actually in the tarball
  5. Record the job — ScanJob (Queued/Received) + ScanBundle (provenance), bytes to disk
                       before the DB row commits, then unitOfWork.CompleteAsync()
  6. Respond         — 202 Accepted, poll URL = /v1/scans/{jobId}
```

Every failure path returns a `Response` with the right `HttpStatusCode` baked in —
`ScanController` just does `StatusCode((int)response.StatusCode, response)`. Nothing after
step 1 is reachable without a valid bearer token carrying the `scan:write` scope.

---

## 3. File-by-file

### API layer

| File | Role |
|---|---|
| `Api/Controllers/ScanController.cs` | `POST /v1/scans`. Binds the two multipart parts into `SubmitScanRequest`, sends the command, maps `Response` → real HTTP status. `[RequestSizeLimit]` mirrors the inspector's 64 MB cap so an oversized upload is rejected before Kestrel buffers it. |
| `Api/DependencyInjection.cs` | Wires JWT bearer auth (`AddAuthentication().AddJwtBearer(...)`, config-bound issuer/audience/signing key) and `UseAuthentication()/UseAuthorization()`. |

### Application layer (`Features/Scan/Commands/Submit/`)

| File | Role |
|---|---|
| `SubmitScanCommand.cs` | `IRequest<Response>` carrying the raw `metadata.json` text and the bundle `Stream`. |
| `SubmitScanCommandValidator.cs` | FluentValidation: both multipart parts must be present. Runs via `ValidationBehavior`, not called by hand. |
| `SubmitScanCommandHandler.cs` | The six steps above. Depends only on interfaces (`IUnitOfWork`, `IBundleInspector`, `IBundleStore`, `ICorpusVersionProvider`, `ICallerContext`) — no EF, no HTTP, so it's testable without either. |
| `SubmitScanResponse.cs` | The 202 body: `ScanJobId`, `Status`, `CorpusVersion`, `PollUrl`, `BundleSha256`, `CreatedAt`. |
| `Common/Behaviors/ValidationBehavior.cs` | Generic MediatR pipeline behavior. Runs every `IValidator<TRequest>` before the handler; a failure becomes a 400 `Response` and the handler never executes. |

### Domain layer (ports + contracts)

| File | Role |
|---|---|
| `Abstractions/IUnitOfWork.cs` | `Repository<TEntity>()` + a dedicated `ScanJobRepository`, `CompleteAsync()` = one `SaveChanges`. |
| `Abstractions/Repositories/IGenericRepository.cs` | Generic CRUD + queryable escape hatches over an EF `DbSet<T>`. |
| `Abstractions/Repositories/IScanJobRepository.cs` | Tenant-scoped job/project lookups. |
| `Abstractions/Repositories/ICallerContext.cs` | Who's calling — `TenantId`, `UserId`, `IsAuthenticated`, `HasScope()`. The **only** abstraction over claims; handlers never touch `HttpContext` directly (that's a deliberate SEC-26 boundary). |
| `Abstractions/Repositories/IBundleInspector.cs` | `InspectAsync(Stream) → BundleInspection` — hash, entries, the source guard, and (see §5) the rewound raw bytes for storage. |
| `Abstractions/Repositories/IBundleStore.cs` | `SaveAsync`/`PurgeAsync` — where bytes live between ingest and the worker. |
| `Abstractions/Repositories/ICorpusVersionProvider.cs` | Which Qdrant corpus snapshot a job will retrieve against, stamped at accept time so an audit is always reproducible. |
| `Enums/ScanStatus.cs` | `Queued \| Running \| Completed \| Failed`. |
| `Enums/ScanStage.cs` | `Received \| Normalize \| Graph \| Retrieve \| Debate \| Report` — where in the pipeline a job currently sits. |
| `Models/BundleMetadata.cs` | Shape of the `metadata.json` multipart part (snake_case on the wire, mirrors `scripts/build-metadata.sh` in `sentinelai-action`). |
| `Models/AuthScopes.cs` | `scan:write`, `scan:read`, `report:read` — string constants, not an enum, because scopes are arbitrary strings arriving in someone else's JWT. |
| `Models/ScanJob.cs` / `Models/ScanBundle.cs` | The two rows this endpoint writes (see §4). |
| `Premitives/Response.cs` | The uniform envelope every handler returns: `IsSuccess`, `StatusCode`, `Message`, `Data`. |

### Infrastructure layer

| File | Role |
|---|---|
| `Implementation/Repositories/TarGzBundleInspector.cs` | Does the real work — see §5. |
| `Implementation/Repositories/FileSystemBundleStore.cs` | Job-scoped directory on disk (`{RootPath}/{scanJobId}/bundle.tar.gz`). Behind an interface so blob storage later is a DI change, not a rewrite. `PurgeAsync` is what SEC-29's retention job calls. |
| `Implementation/Repositories/ScanJobRepository.cs` | `GetProjectForTenantAsync` filters `TenantId` **inside** the query — a cross-tenant request gets `null`, same as a nonexistent project. A 403 here would confirm existence to someone probing IDs. |
| `Implementation/Repositories/GenericRepository.cs` | Thin wrapper over `DbSet<T>`. |
| `Implementation/Repositories/HttpCallerContext.cs` | Reads `tenant_id`, `sub`, and `scope`/`scp` claims off `HttpContext.User`. The one place in the codebase claims are read. |
| `Implementation/Repositories/ConfiguredCorpusVersionProvider.cs` | Returns a configured constant until Pipeline A publishes a real corpus version. |
| `Implementation/UnitOfWork.cs` | Lazily creates one `GenericRepository<T>` per entity type, backed by the same `DbContext` instance. |
| `Data/Configurations/ScanJobConfiguration.cs` | `Status`/`Stage` stored **by name** (`HasConversion<string>()`), matching every other enum in this codebase — see `docs/Data_Contracts.md` §4. |
| `Data/Migrations/20260802175903_AddScanIngestFields.cs` | Adds `ScanJobs.{FailureReason, ModelTierHint, RetainReport, Stage}` and `ScanBundles.{Sha256, SizeBytes, StorageLocator}`. Already applied to the shared dev database. |

### Tests (`tests/SentinelAI.Integration.Tests/Scan/`)

| File | Role |
|---|---|
| `TarGzTestHelper.cs` | Builds real in-memory `.tar.gz` bundles with `System.Formats.Tar` — no fixture files on disk. |
| `BundleIngestTests.cs` | Exercises `TarGzBundleInspector` directly: valid bundle accepted, `.cs` file rejected, missing `findings/` rejected. |
| `FakeScanInfrastructure.cs` | Hand-rolled fakes for the handler's ports (`ICallerContext`, `ICorpusVersionProvider`, `IBundleStore`, `IScanJobRepository`, `IUnitOfWork`/`IGenericRepository<T>`) — this codebase has no mocking library, so these are explicit classes, following the same pattern as `tests/.../Agents/TestDebate.cs`. |
| `SubmitScanCommandHandlerTests.cs` | The two SEC-13 acceptance paths against the **real** inspector + fake everything else: valid bundle → exactly one `ScanJob` + one `ScanBundle` recorded and 202; source-carrying bundle → nothing persisted and 422. |

---

## 4. What gets written

**`ScanJob`** (one row per submission)

| Field | Source |
|---|---|
| `Id` | `Guid.CreateVersion7()` — time-ordered |
| `ProjectId` | resolved from `metadata.project_id`, tenant-checked |
| `TriggeredBy` | `caller.UserId` — **null** for machine tokens, by design |
| `PrRef`, `CommitSha` | from `metadata.json` |
| `Status` | `Queued` |
| `Stage` | `Received` |
| `ModelTierHint` | `metadata.model_tier_hint`, defaults to `auto`, validated against `{auto, economy, premium}` |
| `RetainReport` | `metadata.retain_report` |
| `CorpusVersion` | `ICorpusVersionProvider` at accept time — reproducibility, not retrieval-time |
| `BundlePurged` | `false` (SEC-29 flips this later) |

**`ScanBundle`** (provenance — one row, 1:1 with the job)

| Field | Source |
|---|---|
| `RunnerSecretScan` | `metadata.runner_secret_scan` |
| `ArtifactManifest` | the runner's own `artifacts` list, serialized verbatim |
| `ScannerVersions` | the runner's `scanner_versions` block, verbatim |
| `Sha256`, `SizeBytes` | computed by the inspector over the received bytes |
| `StorageLocator` | wherever `IBundleStore` put it (currently a file path) |
| `IngressRedactionApplied` | `false` — set later, by the redaction stage, not here |

---

## 5. The source guard, in detail

`TarGzBundleInspector.InspectAsync` (`Infrastructure/Implementation/Repositories/TarGzBundleInspector.cs`):

1. **Hash first.** Reads the incoming stream into an in-memory buffer while computing
   SHA-256 incrementally, capped at 64 MB. The digest describes exactly what arrived,
   before anything is interpreted.
2. **Enumerate, don't extract.** Nothing touches disk. Entries are walked with
   `System.Formats.Tar.TarReader`; only `metadata.json`'s content is read into memory
   (needed for the manifest cross-check). Guards against a hostile tarball: entry count
   capped at 5,000, decompressed size capped at 512 MB, and any entry starting with `..`
   or an absolute path is rejected outright (zip-slip / path traversal).
3. **The guard itself** — a regex over every entry name:
   ```
   \.(cs|vb|fs|cshtml|razor|aspx|java|kt|py|rb|php|go|rs|ts|tsx|jsx|c|cc|cpp|h|hpp|m|swift|scala)$
   ```
   `.csproj` and `packages.lock.json` are manifests, not source, and stay allowed. A hit
   is logged at `Error` level (a source file this deep means the runner-side guard failed
   — an Action defect worth chasing, not a routine 400) and the whole bundle is refused.
4. **Shape checks** — must have a root `metadata.json` and at least one `findings/` entry,
   or there's nothing for the next pipeline stage to do.
5. **Return the verdict** — `BundleInspection { IsValid, Error, Entries, MetadataJson,
   Sha256, SizeBytes, RawBundle }`.

### Why `RawBundle` exists

The inspector already reads the caller's stream to completion once, into its own buffer,
to compute the hash. Early code had the handler hand the **original** stream to
`IBundleStore.SaveAsync` afterward — which only works if that original stream is
seekable. An HTTP upload stream is not guaranteed to be (it can be forward-only), so a
second read could silently persist a 0-byte or truncated file while the DB row still
claimed the correct hash and size — a "successful" ingest that corrupts the artifact the
scan pipeline reads later.

The fix: `BundleInspection.RawBundle` is the inspector's own buffer, rewound to position
0, handed back to the caller. `IBundleStore.SaveAsync` reads from that instead of the
original stream — correct regardless of what kind of stream the controller received.
`SubmitScanCommandHandlerTests` asserts the byte count written to the fake store matches
`ScanBundle.SizeBytes`, as a regression guard for exactly this.

---

## 6. Auth (placeholder pending SEC-26)

`ScanController` carries `[Authorize]`; `Api/DependencyInjection.cs` wires a JWT bearer
scheme reading `Authentication:Jwt:{Issuer,Audience,SigningKey}` from configuration:

- `appsettings.json` (committed) ships all three **empty** — auth fails closed by default;
  nothing validates until an environment supplies real values via user-secrets, env vars,
  or `appsettings.Development.json`.
- `appsettings.Development.example.json` has a dev-only placeholder key, clearly marked
  "never reuse this value anywhere real."

`HttpCallerContext` (the only place claims are read) expects:

| Claim | Maps to |
|---|---|
| `tenant_id` | `ICallerContext.TenantId` (GUID) |
| `sub` (`ClaimTypes.NameIdentifier`) | `ICallerContext.UserId` — absent for machine tokens |
| `scope` or repeated `scp` | `ICallerContext.HasScope(...)` — space-delimited or repeated, either form |

This is explicitly a stopgap: a single symmetric signing key is "good enough for the POC,"
matching how `FileSystemBundleStore` describes itself. SEC-26 owns the real identity
story.

---

## 7. Testing it yourself, end to end

The automated tests above prove the *logic*. They don't prove the *wired system* —
that needs a real HTTP round trip. Rough recipe:

1. **Point the app at a real DB.** A connection string in `dotnet user-secrets` for
   `SentinelAI.Api` is enough; the `AddScanIngestFields` migration is already applied to
   the shared dev database, so no `dotnet ef database update` needed unless you're
   pointing at a fresh one.
2. **Set a JWT signing key** the same way (user-secrets or `appsettings.Development.json`):
   `Authentication:Jwt:Issuer`, `:Audience`, `:SigningKey`.
3. **Make sure a `Tenant` + `Project` row exists** — `GetProjectForTenantAsync` returns
   `null` (→ 404) otherwise. Seed one if the DB doesn't have one yet.
4. **Mint a bearer token** signed with that same key, symmetric HMAC-SHA256, claims:
   `tenant_id` = the project's tenant GUID, `scope` = `scan:write`.
5. **Build two test bundles** with plain `tar`/`gzip` — no need for C#:
   - valid: `metadata.json` (with a real `project_id`/`commit_sha`) + a `findings/` entry
   - invalid: same, plus a `.cs` file anywhere
6. **Run the API** (`dotnet run --project src/SentinelAI.Api`) and `curl` both bundles at
   `POST /v1/scans` as `multipart/form-data` — `metadata` as a text part, `bundle` as a
   file part — with the `Authorization: Bearer <token>` header.
7. **Check**: valid → `202` + a poll URL, and new rows in `ScanJobs`/`ScanBundles`;
   invalid → non-2xx with a message naming the offending file.

---

## 8. Known gaps

- No automated test goes through the real HTTP pipeline (controller model binding, JWT
  middleware, a real `DbContext`) — only the handler and inspector are covered directly.
  §7 above is how to close that gap by hand; a `WebApplicationFactory`-based test would
  close it permanently.
- Auth is a placeholder (see §6) — real identity/issuance is SEC-26's.
- `SubmitScanCommandHandler` never cross-checks the multipart `metadata` part against the
  `metadata.json` *inside* the tarball (`BundleInspection.MetadataJson`) — only the
  artifact list is cross-checked. Worth a look if tamper-resistance between the two copies
  ever matters.

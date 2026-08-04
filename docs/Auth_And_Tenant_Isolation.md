# Authentication, RBAC & tenant isolation (SEC-32)

Every request must carry a valid token. What that token is allowed to do depends on its
role. What data it can see is scoped to its tenant, automatically, everywhere — not
per-query. This page is a map of how that's enforced and why it's shaped this way.

Source of truth is the code. Builds on SEC-13's JWT scaffolding — see
`docs/Bundle_Ingest.md` §6 for where auth started.

---

## 1. The three guarantees, and how each is enforced

| Guarantee | Enforced by |
|---|---|
| No token → 401 | `[Authorize]` + JWT bearer middleware (`Api/DependencyInjection.cs`) |
| Wrong role → 403 | `[Authorize(Roles = Roles.Admin)]` on the specific action |
| Cross-tenant read → nothing | An EF Core global query filter, applied automatically to every tenant-owned table |

The first two are ASP.NET Core doing what it's built to do. The third is the one that
needed real design, because "automatic" and "everywhere" are the operative words — SEC-32's
own stated failure mode is "filtering by tenant in some queries but not all."

---

## 2. Tenant isolation: `ITenantOwned` + a reflection-applied filter

### The schema change

`TenantId` is now a column on **every** tenant-owned table, not just `User` and `Project`
(which already had it). `ScanJob`, `ScanBundle`, `Finding`, `GraphNode`, `GraphEdge`,
`Chain`, `ChainHop`, `Report`, `Citation` all gained it — denormalized, set once at
creation, never updated.

### Why denormalize instead of navigating to `Project.TenantId`

The alternative was writing every filter as a join chain —
`j => j.Project!.TenantId == tenantId`, and for something like `Citation` (which hangs off
*either* a `ChainHop` or a `Report`), an `OR` across two navigation paths five joins deep.
That's slower, harder to read, and exactly the kind of thing someone gets subtly wrong
under time pressure. A flat column and an index on it is a one-line equality check no
matter how deep the entity sits in the ownership tree.

`RuleMapping` deliberately does **not** get a `TenantId` — it's global CWE/CVE reference
data, shared across every tenant, not owned by any one of them.

### `ITenantOwned` — the marker interface

```csharp
// SentinelAI.Domain.Abstractions
public interface ITenantOwned
{
    Guid TenantId { get; set; }
}
```

Every tenant-owned model implements it. That's the entire contract a new entity has to
satisfy to be automatically isolated — nothing to remember at the call site, nothing to
add to a config class.

### The filter itself — applied by reflection, not by hand

A per-entity `HasQueryFilter()` call (one in each `IEntityTypeConfiguration<T>`) is still
one forgotten *entity* away from the exact failure SEC-32 warns about — the day someone
adds table #10 and forgets the filter call. `SentinelDbContext.OnModelCreating` instead
walks the model and applies the filter to anything implementing `ITenantOwned`:

```csharp
private void ApplyTenantIsolation(ModelBuilder modelBuilder)
{
    var contextInstance = Expression.Constant(this);

    foreach (var entityType in modelBuilder.Model.GetEntityTypes())
    {
        if (!typeof(ITenantOwned).IsAssignableFrom(entityType.ClrType))
            continue;

        var entity = modelBuilder.Entity(entityType.ClrType);
        entity.HasIndex(nameof(ITenantOwned.TenantId));

        // e => e.TenantId == this.CurrentTenantId
        var parameter = Expression.Parameter(entityType.ClrType, "e");
        var tenantIdProperty = Expression.Property(parameter, nameof(ITenantOwned.TenantId));
        var currentTenantId = Expression.Property(contextInstance, nameof(CurrentTenantId));
        var filter = Expression.Lambda(Expression.Equal(tenantIdProperty, currentTenantId), parameter);

        entity.HasQueryFilter(filter);
    }
}
```

A new tenant-owned entity gets isolated (and indexed) the moment it implements
`ITenantOwned` — there is no second step to forget.

This has to be an **instance** method, not static: the filter closes over `this` so that
`CurrentTenantId` is read from the *live* `SentinelDbContext` at query time, per request —
not baked in once when the model is built.

### `CurrentTenantId` — fail closed, not open

```csharp
public Guid CurrentTenantId { get; }

public SentinelDbContext(DbContextOptions<SentinelDbContext> options, ICallerContext callerContext)
    : base(options)
{
    CurrentTenantId = callerContext.TenantId ?? Guid.Empty;
}
```

No authenticated caller (no HTTP request at all — EF design-time tooling, for instance)
means `CurrentTenantId` is `Guid.Empty`. Since no real row ever has `TenantId == Guid.Empty`,
every filtered query returns nothing rather than everything. Missing context fails safe by
construction, not by a null-check someone has to remember to add.

**Important:** the filter only shapes *reads*. `Add`/`Update`/`SaveChanges` are completely
unaffected by query filters — that's why `SubmitScanCommandHandler` has to set
`TenantId = caller.TenantId.Value` explicitly on every `ScanJob`/`ScanBundle` it creates.
Forgetting that wouldn't be caught by the filter; the row would just be silently
unreadable by anyone, forever, including the tenant that "owns" it.

---

## 3. RBAC

### Roles

```csharp
public static class Roles
{
    public const string Admin = "admin";
    public const string Analyst = "analyst";
    public const string Viewer = "viewer";
}
```

Constants, not an enum — same reasoning as `AuthScopes` (`docs/Bundle_Ingest.md`): a role
is an arbitrary string claim arriving in someone else's JWT, and an unrecognized value
should simply not match rather than fail to parse.

### Enforcement

```csharp
[HttpPost("{id:guid}/purge")]
[Authorize(Roles = Roles.Admin)]
public async Task<IActionResult> Purge(Guid id, CancellationToken ct) { ... }
```

`PurgeScanBundleCommandHandler` re-checks `caller.Role != Roles.Admin` on top of the
attribute — the same defense-in-depth pattern `SubmitScanCommandHandler` already used for
the `scan:write` scope: the middleware gate is the primary enforcement, but the handler is
provably correct on its own too, and is testable without spinning up the HTTP pipeline.

### `GET /v1/scans/{id}` vs `POST /v1/scans/{id}/purge`

SEC-13's `202` response already advertised a poll URL
(`/v1/scans/{jobId}`) that nothing served. `GET /v1/scans/{id}` closes that gap and
doubles as the "any authenticated user" example the ticket asked for.

For the admin-only example, a literal `DELETE /v1/scans/{id}` (mirroring the ticket's
`DELETE /v1/account`) was considered and rejected: `ChainHop`'s foreign keys to `Chain`,
`Finding`, and `GraphEdge` are `DeleteBehavior.Restrict`, not `Cascade`. Cascading a
`ScanJob` delete through populated chains would throw a foreign-key violation the moment
the pipeline actually produces them — an unrelated data-integrity landmine with nothing to
do with SEC-32. `POST /v1/scans/{id}/purge` (calling `IBundleStore.PurgeAsync` — the same
thing SEC-29's retention job does on a schedule) is the admin-gated action instead: real,
small, and orthogonal to that problem.

---

## 4. The claim contract — and the bug that lived in it

Every claim is read by its **raw, short JWT name**, consistently, everywhere:

| Claim | Read by |
|---|---|
| `tenant_id` | `ICallerContext.TenantId` |
| `sub` | `ICallerContext.UserId` — absent for machine tokens |
| `role` | `ICallerContext.Role`, and `[Authorize(Roles=...)]` via `RoleClaimType` |
| `scope` / `scp` | `ICallerContext.HasScope(...)` — either form, space-delimited or repeated |

### Why `MapInboundClaims = false` matters

`JwtSecurityTokenHandler` has a **default, silent** inbound claim mapping that rewrites
certain short claim names to long legacy URIs on the way in — `"role"` becomes
`http://schemas.microsoft.com/ws/2008/06/identity/claims/role` (`ClaimTypes.Role`), `"sub"`
becomes `ClaimTypes.NameIdentifier`. This is a decade-old ASP.NET Core / IdentityModel
default that predates the modern `JwtBearerOptions` API, and it is *not* documented
anywhere near `TokenValidationParameters.RoleClaimType`.

Setting `RoleClaimType = "role"` without also disabling this remap does nothing useful: by
the time the claim reaches `RoleClaimType`'s check, it's already been renamed to
`ClaimTypes.Role`, so `"role"` never matches. **Every** role check failed silently as a
result — including for a token that correctly carried `role: "admin"`. This is not a
theoretical risk: it was caught by the SEC-32 test suite (`Admin_role_can_purge...`
initially failed with 403, not the 200 it should have returned), not by inspection — a
handler-level test with a hand-built `ICallerContext` would never have exercised this path
at all, because it bypasses the JWT pipeline entirely.

The fix, in `Api/DependencyInjection.cs`:

```csharp
.AddJwtBearer(options =>
{
    // JwtSecurityTokenHandler otherwise silently remaps short claim names to long
    // legacy URIs on the way in ("role" -> ClaimTypes.Role, "sub" -> ClaimTypes.NameIdentifier),
    // which would quietly override RoleClaimType and break every role check.
    options.MapInboundClaims = false;
    ...
});
```

With that off, `HttpCallerContext.UserId` had to move from `ClaimTypes.NameIdentifier` to
the raw `"sub"` — the two were only ever accidentally in sync because the *old* default
remap happened to convert one into the other. Every reader (`HttpCallerContext`, tests)
now agrees on raw names, with nothing rewriting them in between.

---

## 5. Testing it yourself, end to end

This is the piece SEC-13 didn't have: a real HTTP-level test harness, not tests that call a
handler directly with a hand-built `ICallerContext` (which can't prove 401/403 exist at
all — the fake is always `IsAuthenticated = true`).

`tests/SentinelAI.Integration.Tests/Auth/`:

| File | Role |
|---|---|
| `ScanApiFactory.cs` | `WebApplicationFactory<Program>` — boots the *real* `Program`, real middleware, against an isolated EF Core in-memory database instead of the shared SQL Server, with a fixed JWT signing key so tests can mint their own tokens. |
| `TestJwt.cs` | Mints HMAC-signed tokens with arbitrary `tenant_id`/`role`/`scope` claims, matching the factory's fixed key. |
| `AuthAndTenantIsolationTests.cs` | The six proofs: no token → 401; viewer → 403 on purge; admin → 200 on purge; same tenant → 200 on read; other tenant → 404 (not 403 — see below); machine token (`scan:write` only, no role) → 403 on purge. |

### Two `WebApplicationFactory` gotchas worth knowing about if you extend this

1. **`ConfigureServices` vs `ConfigureTestServices`.** For a minimal-hosting (top-level
   statement) `Program.cs`, plain `ConfigureServices` callbacks can run *before* the app's
   own `Program.cs` service registration, not after — so a DbContext swap registered there
   gets silently undone when the app's own `AddDbContext(UseSqlServer(...))` call lands
   afterward. `ConfigureTestServices` is guaranteed to run last.
2. **EF Core composes provider configuration additively.** Removing only
   `DbContextOptions<SentinelDbContext>` and `SentinelDbContext` from the service
   collection isn't enough to swap providers — EF Core 10 rebuilds `DbContextOptions<T>`
   from every registered `IDbContextOptionsConfiguration<T>`, so the original
   `UseSqlServer` configuration survives unless everything generically closed over
   `SentinelDbContext` is removed first. `ScanApiFactory.ConfigureWebHost` does this by
   removing every `ServiceDescriptor` whose service type is (or is generic over)
   `SentinelDbContext`, rather than guessing which specific types matter.

### Why cross-tenant is 404, not 403

`GetScanJobQueryHandler` (and the pre-existing `ScanJobRepository.GetForTenantAsync`) treat
"exists but belongs to another tenant" identically to "does not exist." A 403 would leak
existence — it tells an attacker the ID is real, just not theirs. This was already the
design before SEC-32; the global query filter now backs it up as a second, independent
layer: even a query that forgot the explicit tenant check would still come back empty.

### Doing it manually against a live app (not just the test suite)

Same recipe as `docs/Bundle_Ingest.md` §7, plus:

1. Mint a token (`TestJwt`-style, or any JWT library) with `tenant_id`, and for role-gated
   actions, a `role` claim — matching whatever `Authentication:Jwt:SigningKey` the running
   app is configured with.
2. `GET /v1/scans/{id}` with no `Authorization` header → expect `401`.
3. Same request with a token for a *different* tenant than the job's owner → expect `404`.
4. `POST /v1/scans/{id}/purge` with a token carrying `role: viewer` (or no role) →
   expect `403`.
5. Same request with `role: admin` for the job's own tenant → expect `200`, and
   `ScanJob.BundlePurged` flips to `true`.

---

## 6. Known gaps

- Auth is still a placeholder pending SEC-26 (single symmetric signing key, no real
  identity provider / token issuance flow) — unchanged from SEC-13, just now with roles
  layered on top of the same mechanism.
- No test proves the *`Analyst`* role's boundaries specifically — only `Viewer` (rejected)
  and `Admin` (accepted) are exercised, since no analyst-gated action exists yet. Worth
  adding once one does.
- `RuleMapping` is the only model deliberately excluded from `ITenantOwned`. If a future
  table is genuinely global/shared like it, it needs the same deliberate exclusion — the
  reflection loop isolates by default, which is correct for tenant-owned data and wrong
  for reference data, so this one judgment call doesn't go away just because the rest is
  automatic.

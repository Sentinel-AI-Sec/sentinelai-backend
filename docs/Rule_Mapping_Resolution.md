# Rule-mapping resolution (SEC-15)

Some scanners report a rule and no CWE. `CKV_AWS_20` is a real, high-severity finding, but
with no linking key it is invisible to everything downstream — the RAG exact filter, the
graph decoration, the chain hops all join on CWE or CVE. This step closes that gap by
looking the CWE up in a table, keyed on the tool's own rule id.

It is deliberately the least clever component in the pipeline: `WHERE source_tool = @tool
AND check_id = @id`. No similarity, no embeddings, no model call.

Source of truth is the code. This page is a map of it.

---

## 1. Why it's shaped this way

Three constraints drive every decision here:

1. **Determinism is the entire value.** A finding's CWE decides which knowledge it retrieves
   and which node it can chain through. If that answer came from a similarity search, two
   runs of the same scan could produce different chains and the benchmark numbers would mean
   nothing. An exact lookup against a unique index always gives the same answer or no answer,
   and "no answer" is a normal, honest outcome.
2. **The scanner outranks the table.** When a tool reports a CWE it saw the actual result;
   the table only ever knows the rule in the abstract. So a finding that already carries a
   CWE is never touched — a mapping may only fill a gap, never overwrite.
3. **The persisted `Finding` shape is fixed (SEC-03 / D2 database design).** The rule id has
   to travel from the extractor to the lookup, but the `findings` table has no `check_id`
   column and must not grow one. See §4.

---

## 2. Where it sits in the flow

```
NormalizationPipeline.NormalizeAsync                [SentinelAI.Application]
  │
  ├─ for each findings file → IFindingExtractor     [SentinelAI.Infrastructure]   SEC-14
  │     roslyn.sarif   → RoslynSarifExtractor
  │     osv.json       → OsvJsonExtractor
  │     trivy.sarif    → TrivySarifExtractor
  │     checkov*.sarif → CheckovSarifExtractor
  │     each Finding carries CheckId = the tool's rule id (in-pipeline only)
  │
  ▼
  RuleMappingResolver.ResolveAsync(findings)        [SentinelAI.Application]      SEC-15
  │  1. select findings where CweId is null AND CheckId is not null
  │  2. reduce to the distinct (SourceTool, CheckId) keys
  │  3. one batched exact lookup
  │  4. write the resolved CWE back onto the findings; leave the rest as they are
  │
  ▼
  IRuleMappingLookup ── SqlRuleMappingLookup        [SentinelAI.Infrastructure]
  │  SELECT CweId FROM RuleMappings
  │  WHERE SourceTool = @tool AND CheckId IN (@ids) AND CweId IS NOT NULL
  │
  ▼
  one combined List<Finding>, as many of them linkable as the table can make them
      → SEC-16 unifies and dedupes this list
```

Resolution runs **after** extraction rather than inside it, on purpose. The extractors are
pure synchronous parsers with no database and no `async`; putting a query inside them would
mean a round trip per SARIF result. One batched lookup per bundle does the same work in a
couple of queries.

---

## 3. File-by-file

### Application layer

| File | What it is |
|---|---|
| `Abstractions/IRuleMappingLookup.cs` | The port. `ResolveCwe(sourceTool, checkId)` is the single exact lookup from the task spec; `ResolveCweAsync(keys, ct)` is the same predicate asked in bulk. Also defines `RuleKey`, the (tool, check id) pair used as the lookup key. |
| `Features/Scan/Normalization/RuleMappingResolver.cs` | The step itself. Picks out the findings with a gap, asks once, writes the answers back, returns how many it filled. Depends only on the port, so it tests against a dictionary. |
| `Features/Scan/Normalization/NormalizationPipeline.cs` | Now takes `RuleMappingResolver` and calls it after extraction. Its completion log line also reports how many findings still carry no linking key at all. |
| `DependencyInjection.cs` | Registers `RuleMappingResolver` scoped. |

### Infrastructure layer

| File | What it is |
|---|---|
| `Normalization/SqlRuleMappingLookup.cs` | The adapter. EF Core over `SentinelDbContext.RuleMappings`, `AsNoTracking`, plain equality. The batch form groups keys by tool so both halves of the key stay in the `WHERE` clause. |
| `Data/Configurations/RuleMappingConfiguration.cs` | The unique index on (`SourceTool`, `CheckId`) plus the seeded starter map — 13 rows across roslyn / checkov / trivy. |
| `Data/Configurations/FindingConfiguration.cs` | `builder.Ignore(f => f.CheckId)` — the rule id is transport, not a column. |
| `Normalization/SarifFindings.cs`, `Normalization/OsvJsonExtractor.cs` | Stamp `CheckId` onto each finding as it is built. |
| `Data/Migrations/20260805092840_SeedRuleMappings.cs` | Inserts the 11 new mapping rows. Data only — no schema change, which is the proof that `Finding.CheckId` added no column. |
| `DependencyInjection.cs` | Registers `IRuleMappingLookup → SqlRuleMappingLookup` scoped. |

### Domain layer

| File | What it is |
|---|---|
| `Models/Finding.cs` | Gains `CheckId`, documented as in-pipeline only. |
| `Models/RuleMapping.cs` | Unchanged — the entity was already defined. |

### Tests

| File | What it covers |
|---|---|
| `Infrastructure.Tests/Normalization/RuleMappingResolverTests.cs` | 8 tests: fills a gap, never overwrites, never guesses, tool is part of the key, no check id means no query, repeats cost one lookup, case-insensitive matching, empty input. |
| `Infrastructure.Tests/Normalization/FakeRuleMappingLookup.cs` | In-memory stand-in for the table; counts calls so the "one lookup, not N" claim is asserted, not assumed. |
| `Infrastructure.Tests/Normalization/NormalizationPipelineTests.cs` | 2 new tests: the pipeline resolves CWEs end to end from real SARIF fixtures, and an empty table changes nothing. |
| `Integration.Tests/Scan/SqlRuleMappingLookupTests.cs` | 7 tests against a real EF provider: exact match, no near-match on a prefix, per-tool namespacing, null CWE rows, the batch form, empty input, and a guard that `Finding.CheckId` is not mapped to a column. |
| `Integration.Tests/Scan/RuleMappingWiringTests.cs` | 3 tests through the app's own DI container and the real seeded table: the container resolves the lookup/resolver/pipeline, the 13 seed rows land in a created database with no duplicate key, and a real Checkov finding resolves end to end. These catch what the others structurally cannot — a missing DI registration, or seed rows dropped from a migration. |

---

## 4. Carrying the rule id without widening the contract

The lookup key is (tool, rule id), but only the extractor ever sees the rule id, and the
`findings` table has no `check_id` column — by design, in the D2 database document. Two ways
to bridge that:

- change `IFindingExtractor` to return a wrapper carrying the rule id alongside the finding —
  touches SEC-14's port and all four extractors; or
- put the rule id on `Finding` and map it out of the model.

This took the second. `Finding.CheckId` is a plain property that
`FindingConfiguration.Ignore` keeps out of the schema, so:

- the **persisted** shape is byte-identical to before — the generated migration contains
  `InsertData` and nothing else, and `SentinelDbContextModelSnapshot` shows no `CheckId`
  under `Finding`;
- SEC-14's extractor port is unchanged;
- the rule id lives exactly as long as the normalization run and is spent resolving the CWE.

`SqlRuleMappingLookupTests.Findings_are_not_widened_by_the_check_id_the_lookup_uses` asserts
this against the built EF model, so if the `Ignore` is ever dropped the test fails rather
than a stray column appearing in a migration.

One other note: the task spec's snippet writes `finding = finding with { CweId = cwe }`,
which assumes a record. `Finding` in this codebase is a mutable EF entity class, so the
resolver assigns `finding.CweId` in place — same effect, no copy.

---

## 5. The lookup table

`rule_mappings` is **global reference data**: `RuleMapping` deliberately does not implement
`ITenantOwned`, so no tenant query filter applies and every tenant resolves against the same
map. `SqlRuleMappingLookupTests` builds its context with a caller that has *no* tenant —
which would hide every tenant-scoped row — and the lookups still succeed, which is the
assertion that this is really shared.

The unique index on (`SourceTool`, `CheckId`) is what makes the lookup a lookup: two rows for
one rule would make CWE resolution nondeterministic, so the database refuses them rather than
letting the pipeline pick one.

Seeded rows (a starter map for the rules the current toolchain reports without a CWE, not a
complete catalogue):

| tool | check_id | cwe_id | |
|---|---|---|---|
| roslyn | SCS0001 | CWE-78 | command injection |
| roslyn | SCS0005 | CWE-338 | weak random number generator |
| roslyn | SCS0018 | CWE-22 | path traversal |
| roslyn | SCS0026 | CWE-89 | SQL injection |
| roslyn | SCS0028 | CWE-502 | insecure deserialization *(pre-existing)* |
| roslyn | SCS0029 | CWE-79 | cross-site scripting |
| checkov | CKV_AWS_18 | CWE-778 | S3 access logging not enabled |
| checkov | CKV_AWS_19 | CWE-311 | S3 not encrypted at rest |
| checkov | CKV_AWS_20 | CWE-284 | S3 public read *(pre-existing)* |
| checkov | CKV_AWS_24 | CWE-284 | security group allows 0.0.0.0/0 → port 22 |
| checkov | CKV_DOCKER_3 | CWE-250 | container has no non-root user |
| trivy | AVD-AWS-0086 | CWE-284 | S3 public access block missing |
| trivy | AVD-AWS-0089 | CWE-778 | S3 bucket access logging disabled |

OSV has no rows on purpose: its advisories already carry CVE/GHSA ids and usually a CWE, so
there is no gap to fill.

The table grows **by migration**, not by hand-editing the database. Mappings have real
consequences for what gets linked into a chain, so a change to them should be reviewed and
versioned like any other schema change.

---

## 6. How to verify it

### 6.1 Run everything

```bash
dotnet test SentinelAI.slnx
```

Expected: `Infrastructure.Tests` 22 passed, `Integration.Tests` 67 passed.
`Domain.Tests` has one **pre-existing, unrelated** failure —
`NodeIdTests.Every_node_id_in_the_debate_brief_is_canonical` expects 5 node keys but
`ScanBrief.Stub()` now lists 9. It is untouched by SEC-15.

### 6.2 Just this task's tests

```bash
dotnet test SentinelAI.slnx --filter RuleMapping
```

18 tests: 8 resolver, 7 SQL lookup, 3 wiring. Add `-v n` to see them by name — the names are
written to be read as the specification. SEC-15's two pipeline tests are not caught by that
filter — they sit in the class that also holds SEC-14's two, so this runs 4:

```bash
dotnet test tests/SentinelAI.Infrastructure.Tests --filter NormalizationPipelineTests
```

### 6.3 Against a real SQL Server

The tests above use EF's in-memory provider, which does not enforce the unique index or run
real T-SQL. To check the migration and the index for real, point
`ConnectionStrings:DefaultConnection` at a server (LocalDB is the zero-setup Windows default,
already in `appsettings.Development.example.json`) and apply the migrations:

```bash
dotnet ef database update --project src/SentinelAI.Infrastructure --startup-project src/SentinelAI.Api
```

Then confirm the seed landed and the key is unique:

```sql
SELECT SourceTool, CheckId, CweId FROM RuleMappings ORDER BY SourceTool, CheckId;
-- 13 rows

SELECT SourceTool, CheckId, COUNT(*) FROM RuleMappings
GROUP BY SourceTool, CheckId HAVING COUNT(*) > 1;
-- 0 rows; inserting a duplicate must fail on the unique index
```

### 6.4 What each layer of test actually rules out

| Level | Fails when… |
|---|---|
| `RuleMappingResolverTests` (fake table) | the resolver overwrites a scanner's CWE, guesses at an unmapped rule, matches across tools, or asks per-finding instead of per-rule |
| `SqlRuleMappingLookupTests` (real EF provider) | the query is not exact — a prefix or near match resolves — or `Finding.CheckId` starts being mapped to a column |
| `NormalizationPipelineTests` (real SARIF fixtures) | the rule id is lost between the extractor and the resolver |
| `RuleMappingWiringTests` (real DI container + seeded table) | `IRuleMappingLookup` is not registered, or the seed rows are missing/duplicated — the two failures that leave every other test green while production resolves nothing |
| §6.3, by hand | the migration does not apply, or the unique index is not really on the table |

### 6.5 What cannot be tested end to end yet

There is no full request-to-findings path to exercise: SEC-13 accepts a bundle, writes a
`Queued` job and returns `202`, and the worker that drains that queue and calls
`NormalizationPipeline` does not exist yet. `NormalizationPipelineTests` is the closest thing
— real SARIF in, resolved findings out — and it stops at the pipeline's return value.

---

## 7. Acceptance checks (SEC-15)

| The task asks | Where it is proved |
|---|---|
| A finding with no CWE gets one by exact (tool, check_id) lookup | `RuleMappingResolverTests.Fills_a_missing_cwe_from_the_exact_check_id` — the spec's own `CKV_AWS_20 → CWE-284` example — plus `NormalizationPipelineTests.Findings_with_no_cwe_get_one_from_the_rule_mapping_table` from real SARIF, and `RuleMappingWiringTests.A_real_checkov_finding_with_no_cwe_is_resolved_by_the_wired_pipeline` against the actual seeded table |
| The lookup is a plain query — no embeddings, no similarity, no AI | `SqlRuleMappingLookup` is a `Where(...).Select(...).FirstOrDefault()`. `SqlRuleMappingLookupTests.An_absent_row_returns_null_not_a_near_match` seeds `CKV_AWS_20` and asserts that `CKV_AWS_2` and `CKV_AWS_200` both resolve to nothing — a `LIKE`/contains query would pass one of them |
| Findings that already have a CWE are left alone | `RuleMappingResolverTests.Leaves_a_finding_that_already_has_a_cwe_untouched` — the table is seeded with a *different* CWE for that rule and the scanner's answer wins |

---

## 8. Known gaps

- **`cve_id` on the mapping table is written but never read.** The column exists and the
  seed rows leave it null. Only CWE resolution is in SEC-15's acceptance list, and a CVE is a
  claim about a specific vulnerable package rather than about a rule, so mapping one from a
  rule id would usually be wrong. Left for whoever needs it.
- **The seed map is small.** Thirteen rows covers the rules that turn up in the fixtures and
  the common S3/IAM/Docker checks. Real coverage comes from watching the "still carry no CWE"
  count in the pipeline's completion log and adding the rules that actually appear.
- **No cache across scans.** The table is read once per scan run. It is small, static
  reference data and would cache well, but per-run is not currently a measured cost.
- **Nothing consumes the pipeline output yet.** See §6.5.

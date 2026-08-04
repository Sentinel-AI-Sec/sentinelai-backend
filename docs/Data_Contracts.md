# Canonical data contracts (SEC-03)

The shapes every part of SentinelAI passes around, and the one strict rule for naming
things. **The GitHub Action repo mirrors this document at the bundle boundary** — if the two
drift, findings arrive that can never be joined to nodes.

Source of truth is the code, not this page: `src/SentinelAI.Domain/`.

---

## 1. The naming rule

Every node has a **node key** of the form `type:identifier`, always trimmed, always
lower-cased.

```
pkg:commons-collections:3.2.1
code:appdatahandler.deserialize()
iam_role:api-task-role
s3:customer-data-bucket
```

### Why this rule exists

If the Terraform reader emits `iam_role:Order` and the finding normalizer emits
`role:order`, the system treats them as two different things. The graph splits into
disconnected islands, **zero attack chains are found, and nothing errors** — it looks
exactly like a clean scan. That failure is silent, which is why the rule is centralized in
code and pinned by tests rather than written down and hoped for.

### The rule in code

`SentinelAI.Domain.ValueObjects.NodeId` is the only thing allowed to build a node key.

```csharp
NodeId.Role("Order")      // "iam_role:order"
NodeId.Role(" order ")    // "iam_role:order"  — same key, and that is the point
NodeId.Package("commons-collections:3.2.1")
NodeId.For(NodeType.Resource, "Customer-Data-Bucket")
```

**If you see `"pkg:" + name` anywhere, that is a bug.** There is deliberately no
`For(string type, ...)` overload — the type is a `NodeType`, so an invented type is a
compile error instead of a disconnected island.

Reading a key back:

```csharp
NodeId.TryParse("pkg:commons-collections:3.2.1", out var type, out var id);
// type = NodeType.Pkg, id = "commons-collections:3.2.1"   — splits on the FIRST colon only
NodeId.IsCanonical("iam_role:Order");   // false — someone built this by hand
```

### The type vocabulary

| `NodeType` | Wire prefix | What it is |
|---|---|---|
| `Pkg` | `pkg` | A dependency package |
| `Code` | `code` | A code symbol |
| `Image` | `image` | A container image |
| `Task` | `task` | A deployed workload, e.g. an ECS task definition |
| `IamRole` | `iam_role` | An IAM role |
| `Resource` | `s3` | A cloud resource holding data |

These prefixes cross repository boundaries. **Changing one is a cross-repo breaking change,
not a rename.** They live in a single switch — `NodeTypeExtensions.Prefix()` — so a change
is one edit and one failing test, never a hunt through string literals.

> `Resource` → `s3` is inherited from the SEC-03 spec, written when the demo fixture's crown
> jewel was a bucket. It is kept as-is because SEC-04's fixtures and SEC-06's corpus already
> emit it. Widening it to `resource` is a team decision.

---

## 2. The five contracts

`src/SentinelAI.Domain/Models/`. They are mutable classes rather than records because EF
Core materializes them — the persistence model and the contract are the same types here.

### Finding
What a scanner reported.

| Field | Type | Notes |
|---|---|---|
| `SourceTool` | `string` | `semgrep` \| `roslyn` \| `dependency-check` \| `trivy` \| `checkov` |
| `Layer` | `Layer` | `Code` \| `Dep` \| `Infra` |
| `Severity` | `int` | 0 lowest → 4 highest |
| `CweId`, `CveId` | `string?` | Either may be absent |
| `NodeRef` | `string` | **A node key.** Build it with `NodeId`. |
| `Redacted` | `bool` | Set when the message held customer data |

### GraphNode
One thing in the map.

| Field | Type | Notes |
|---|---|---|
| `NodeKey` | `string` | Canonical. Unique per scan job. |
| `NodeType` | `NodeType` | Must agree with `NodeKey`'s prefix |
| `Layer` | `Layer` | |
| `IsHot` | `bool` | True when a high-severity finding lands on it |

Build with the factory, which sets key and type together:

```csharp
GraphNode.Create(tenantId, scanJobId, NodeType.Resource, "Customer-Data-Bucket", Layer.Infra);
```

### GraphEdge
A connection between two nodes. **Every edge carries a seam and a confidence.**

| Field | Type | Notes |
|---|---|---|
| `Relation` | `string` | `used-by` \| `built-into` \| `deployed-as` \| `assumes` \| `can-access` |
| `Seam` | `Seam` | `InfraSpine` \| `DepCode` \| `CodeInfra` \| `RoleResource` |
| `Confidence` | `Confidence` | `Unresolved` \| `Inferred` \| `Certain` |
| `OrientedAttackDir` | `bool` | The edge points the way an attacker moves |

### Chain
An ordered path of hops.

| Field | Type | Notes |
|---|---|---|
| `HopCount`, `Priority` | `int` | |
| `Status` | `ChainStatus` | `Candidate` \| `Asserted` \| `Validated` \| `Rejected` |
| `MinConfidence` | `Confidence` | **The weakest join in the chain.** See §3. |

### Report
The adjudicated output. `Framing` is always draft-audit, never a verdict (AID-01 §7).

---

## 3. The weakest-link rule

AID-01 §3.3: **a chain is only as trustworthy as its least-confident join.** One unresolved
hop marks the whole chain for human review.

```csharp
chain.MinConfidence = hops.Weakest(h => h.Edge.Confidence);
```

`Confidence` is ordered weakest-first (`Unresolved=0, Inferred=1, Certain=2`) so the rule
stays a one-liner. Use `ConfidenceExtensions.Weakest()` rather than `Min()` — the ordering is
load-bearing, and the named method is what tells the next reader that.

The debate and the graph share this one enum on purpose. The Red/Blue/Reporter debate emits
a `Confidence` on every turn, and `DraftAudit.WeakestJoin` is the same type a `GraphEdge`
carries — so a debate verdict is writable onto an edge with no translation table. Two enums
for one concept is how that quietly stops being true.

### Confidence tiers

| Tier | Meaning | How it is reported |
|---|---|---|
| `Certain` | Confirmed against the real configuration | Normally |
| `Inferred` | Convention-based, e.g. an image-name match | Usable, flagged for scrutiny |
| `Unresolved` | Could not be confirmed | "Potential chain, unverified join" — never a confirmed result |

`Unresolved` means *unconfirmable*, **not** *refuted*. A chain with an unresolved hop is
surfaced for a human, not dropped.

---

## 4. Persistence notes

Every enum is stored **by name** via `HasConversion<string>()`, never by ordinal. Two
consequences:

- Enum members can be reordered without a migration or a data fix.
- Renaming a member **is** a breaking data change.

Storing `Confidence` by ordinal would make its weakest-first ordering permanent, which is
the reverse of what you want — the ordering should be free to change and the *name* fixed.

---

## 5. Checklist for a new extractor

- [ ] Every node key comes from `NodeId`. No string concatenation.
- [ ] Every node built with `GraphNode.Create`, so key and type agree.
- [ ] Every edge carries a `Seam` and a `Confidence`.
- [ ] An unconfirmable join is `Unresolved`, not dropped and not `Certain`.
- [ ] Chain confidence computed with `.Weakest()`, never assigned by hand.

Tests: `tests/SentinelAI.Domain.Tests/NodeIdTests.cs` and `DebateContractTests.cs`.

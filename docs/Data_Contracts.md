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

### Two granularities, and how they join (SEC-20)

A canonical key is not enough on its own, because two stages legitimately key the same thing at
different grains:

| Thing | What the scanner reports | What the graph reader builds |
|---|---|---|
| A package | `pkg:newtonsoft.json:12.0.1` | `pkg:newtonsoft.json` |
| A project | `code:src/orderapp/controllers/orderscontroller.cs` | `code:orderapp` |
| An IAM role | `s3:infra/iam.tf` | `iam_role:order_task_role` |

Both sides are canonical. Neither is wrong — a scanner reports the finest subject it saw, a
reader reports the structure it parsed. Left unjoined they are the island bug all over again:
findings with no nodes, nodes with no findings, **no hot seeds, and therefore zero chains, with
nothing erroring.**

`GraphDecorator` is the join, and every rule it applies is a demonstrable identity rather than a
similarity score:

- **Package** — drop the version. Same package; never the reverse, since adding a version to a
  node key would invent a coordinate nothing reported.
- **Code** — the file belongs to the project whose directory is one of its own path segments,
  deepest first. A file's *own name* never claims it, or `src/billing/orderapp.cs` would be
  claimed by `code:orderapp`.
- **Infra** — `IInfraFindingLocator` resolves `path:line` to the Terraform block containing it.
  A block with no canonical node type (`aws_iam_role_policy`, `aws_s3_bucket_versioning`) exists
  to configure one that has, and names it literally, so the finding decorates *that* resource.

A finding no rule places stays **unattached and counted**. Attaching it to a plausible-looking
node would seed candidate chains describing an attack on something nobody reported.

---

## 2. The five contracts

`src/SentinelAI.Domain/Models/`. They are mutable classes rather than records because EF
Core materializes them — the persistence model and the contract are the same types here.

### Finding
What a scanner reported.

| Field | Type | Notes |
|---|---|---|
| `SourceTool` | `string` | `roslyn` \| `osv` \| `trivy` \| `checkov` — see `ScannerNames` |
| `Layer` | `Layer` | `Code` \| `Dep` \| `Infra` |
| `Severity` | `int` | 0 lowest → 4 highest |
| `CweId`, `CveId` | `string?` | Either may be absent |
| `NodeRef` | `string` | **A node key.** Build it with `NodeId`. |
| `Redacted` | `bool` | Set when the message held customer data |
| `CheckId` | `string?` | *Not persisted.* The tool's own rule id, e.g. `CKV_AWS_20` |
| `Location` | `string?` | *Not persisted.* Repo-relative `path` / `path:line`, or `name@version` for a dependency |

**The two in-pipeline fields.** `CheckId` and `Location` are `Ignore`d in
`FindingConfiguration` — the D2 `findings` table has neither column, and the contract is fixed
(SEC-03). They carry from the extractor to the steps that spend them, and the durable results
are `CweId` and `NodeRef`, which *are* in the contract:

- `CheckId` resolves a missing `CweId` from `rule_mappings` (SEC-15), and — with `Location` —
  tells two findings at the same place apart when unifying (SEC-16). Checkov reports
  `CKV_AWS_288`, `_289` and `_290` on the very same Terraform line and they are three different
  problems, so a dedup key without the rule id deletes two of them silently.
- `Location` is the subject `NodeRef` is built from.

`Location` is normalized on the way in and this is load-bearing: Roslyn and OSV-Scanner emit the
build agent's absolute author path
(`file:///C:/Users/…/sentinelai-fixture/src/OrderApp/…`). Left as-is it reaches both the dedup
key and the node key, so the same finding scanned on two machines becomes two findings on two
nodes, silently. `Infrastructure/Normalization/SourcePath` is what prevents that.

**Who fills `NodeRef`.** Not the extractors — they leave it empty. The unify step (SEC-16)
builds it through `NodeId` from the layer and the location: `Dep` → `pkg:`, `Code` → `code:`,
`Infra` → a resource key. It is file-grained today because a file path is the finest subject the
scanners report; when the Terraform and code readers land (SEC-17/SEC-18) it tightens to
resource- and symbol-grained keys.

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
| `Relation` | `string` | `used-by` \| `built-into` \| `runs-as` \| `deployed-as` \| `assumes` \| `can-access` |
| `Seam` | `Seam` | `InfraSpine` \| `DepCode` \| `CodeInfra` \| `RoleResource` |
| `Confidence` | `Confidence` | `Unresolved` \| `Inferred` \| `Certain` |
| `OrientedAttackDir` | `bool` | The edge points the way an attacker moves |

Which relation each seam emits today:

| Relation | From → to | Seam | Confidence |
|---|---|---|---|
| `used-by` | package → code | `DepCode` | `Certain` — a lock file is explicit |
| `runs-as` | code → image | `CodeInfra` | the image-name match's own tier |
| `deployed-as` | code → task | `CodeInfra` | the same tier — same evidence |
| `assumes` | task → role | `InfraSpine` | `Certain` — `task_role_arn` is explicit |
| `can-access` | infra → infra | `InfraSpine` | `Certain` — reversed Terraform dependency |
| `can-access` | role → resource | `RoleResource` | `Certain` — an IAM statement |

`runs-as` and `deployed-as` both come out of one image-name match. The image node records
*what was compared*; the task node is *where the code runs*, and it is the one a chain walks —
an attacker does not move "into an image", and spending a hop of the 3–4 hop budget on a node no
scanner reports on would push the flagship chain over the cap.

### Chain
An ordered path of hops.

| Field | Type | Notes |
|---|---|---|
| `HopCount` | `int` | **Edges traversed**, so a 4-hop chain has five hop rows |
| `Priority` | `int` | Rank among one traversal's candidates, 1 = read first |
| `Status` | `ChainStatus` | `Candidate` \| `Asserted` \| `Validated` \| `Rejected` |
| `MinConfidence` | `Confidence` | **The weakest join in the chain.** See §3. |

### ChainHop
One position on a chain: the node reached, the edge that reached it, the finding decorating it.

| Field | Type | Notes |
|---|---|---|
| `HopOrder` | `int` | Zero-based; hop 0 is the seed |
| `EdgeId` | `Guid?` | **Null on the seed hop** — it arrived from nowhere |
| `FindingId` | `Guid?` | **Null when no scanner reported on this node** |
| `TechniqueId` | `string` | Empty on a candidate; Red fills it |
| `BlueValidated` | `bool` | False on a candidate; Blue sets it |

> **`finding_id` is nullable, which widens the D2 schema (SEC-20).** A hop is a place on a real
> edge, and plenty of such places carry no finding — a container image, a task definition, an
> IAM role nobody wrote a rule about. Requiring one would mean either dropping those hops, which
> breaks the chain, or inventing one, which fabricates a result. Migration:
> `MakeChainHopFindingOptional`.

A hop has no node column, by design: the node is `Edge.ToNode`, and the seed node is the first
edge's `FromNode`. Storing it again would duplicate a join `graph_edges` already holds.

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
- [ ] If it emits a new node grain, `GraphDecorator` has a rule that joins findings to it.

Tests: `tests/SentinelAI.Domain.Tests/NodeIdTests.cs`, `DebateContractTests.cs` and
`AttackTacticTests.cs`.

---

## 6. Bounded chaining (SEC-20)

`ExploitChainTraverser` turns the decorated graph into the candidate set the debate reasons
inside. Four bounds, each closing a different failure:

| Bound | Rule | Without it |
|---|---|---|
| Hot seeds | a walk starts only at a node a severity ≥ 3 finding landed on | every node is a start; the candidate set *is* the graph |
| Hop cap | ≤ 4 edges (AID-01 §3.2's "3–4 hops") | search is unbounded in a dense graph |
| Cross-layer | ≥ 2 distinct layers | a "chain" that is one finding with extra steps |
| Tactic order | a step may not move backwards along the ATT&CK ladder | reversal artifacts become plausible-reading nonsense |

The tactic ladder is `AttackTactic`, ordered by ATT&CK's own `TA` ids:

```
Pkg → InitialAccess (TA0001)  <  Code, Image → Execution (TA0002)
     <  Task → Persistence (TA0003)  <  IamRole → PrivilegeEscalation (TA0004)
     <  Resource → Collection (TA0009)
```

This is what discards the `iam_role → task` edges the infra spine produces by blanket-reversing
Terraform's dependency graph. Those are *real* edges pointing the wrong way for an attacker; the
correctly-oriented `task → role` `assumes` edge is read separately from the task definition's own
role reference, and SEC-17's reversal is left exactly as written.

Ranking, in order: chains reaching a crown-jewel `Resource`; then strongest weakest-link; then
finding severity; then fewer hops; then node keys, so the order is total and two runs over one
graph produce the same list. Only maximal paths survive — a path another path continues is
dropped.

Everything a traversal produces is `ChainStatus.Candidate`. It found a path; it did not assert
an attack.

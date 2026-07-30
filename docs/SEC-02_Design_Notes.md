# SEC-02 — Agent Orchestration Skeleton

## Implementation & design notes

**Story:** SEC-02 · 8 points · P0 · Sprint 1
**Repo area:** `AgentsProject` (destined for `Sentinel-AI-Sec/backend`, project `Agents`)
**Built:** 28 July 2026
**Status:** Complete — 32 tests, 0 warnings, runs fully offline

> Written against the stub provider. For what changed once real models were connected —
> including one open defect — see [Live_Model_Findings.md](Live_Model_Findings.md).

---

## 1. What the story asked for

SEC-02 is the sprint's designated top technical risk. The Sprint 1 board states it as six steps:

1. Add the Microsoft Agent Framework package to the Agents project.
2. Define three stub agents (Red, Blue, Reporter) that append a message to shared session state.
3. Wire them into a group-chat workflow with an Orchestrator running Red→Blue→Reporter.
4. Add session state persisting across turns; add a turn-cap that stops the loop.
5. Add checkpointing: serialize state after each turn; resume from last checkpoint on restart.
6. Test the three acceptance criteria.

The acceptance criteria are the real specification:

| # | Criterion |
|---|-----------|
| AC1 | Run starts → three agents execute in sequence sharing session state |
| AC2 | Mid-run failure → resume from checkpoint without re-running completed turns |
| AC3 | Turn-cap exceeded → orchestrator terminates cleanly; Reporter still outputs |

Everything below exists to satisfy one of those three, or to keep a documented invariant
from `SentinelAI_AI_Design_Workflow.md` (AID-01) from being quietly broken later.

---

## 2. Method: verify the framework, do not recall it

The first substantive decision was not to write any code against Microsoft Agent Framework
from memory.

The design documents name "Microsoft Agent Framework 1.0". A NuGet search returned the
actual shipping packages:

```
Microsoft.Agents.AI                1.15.0
Microsoft.Agents.AI.Abstractions   1.15.0
Microsoft.Agents.AI.Workflows      1.15.0
Microsoft.Agents.AI.OpenAI         1.15.0
```

Rather than guess at the API surface of a fast-moving 1.x library, a throwaway console app
referencing the packages dumped every public type and member by reflection. That dump —
not documentation, not recall — is what the implementation was written against.

**Why this mattered.** The dump revealed three things that would each have caused a
significant rewrite if assumed wrong:

- **Checkpointing is native.** `CheckpointManager.CreateInMemory()`,
  `FileSystemJsonCheckpointStore`, `InProcessExecution.ResumeAsync(...)`, and
  `CheckpointableRunBase.Checkpoints` already exist. SEC-02 step 5 says "serialize state
  after each turn" — implementing that by hand would have been wasted effort *and* would
  have duplicated a mechanism the framework already applies per superstep.
- **Shared state has a first-class home.** `IWorkflowContext.QueueStateUpdateAsync` /
  `ReadOrInitStateAsync` with a named scope is the supported way for executors to share
  memory, and is exactly what the checkpointer snapshots. Using instance fields would have
  produced state that looked shared but vanished on resume.
- **Conditional edges exist.** `WorkflowBuilder.AddEdge(source, target, Func<T,bool>)`
  makes the turn-cap a property of the graph rather than a counter threaded through agents.

### Version note for the sprint record

The board's "Agent Framework 1.0" and the shipped 1.15.0 are the same 1.x GA line; 1.15.0
is pinned. Separately, the .NET 10 SDK emits the newer `.slnx` solution format rather than
`.sln` — harmless, but worth knowing before someone hunts for a missing `.sln`.

---

## 3. Architecture

```
src/SentinelAI.Agents/
  Contracts/      DebateTurn, DebateState, DraftAudit, AgentRole, JoinConfidence
  Providers/      IChatClientFactory, ChatClientFactory, ScriptedChatClient, options
  Executors/      OrchestratorExecutor, RedTeamExecutor, BlueTeamExecutor, ReporterExecutor
  Orchestration/  DebateWorkflow (the graph), DebateRunner (run/resume), DebateOptions
```

### 3.1 The graph

```
Orchestrator ──> Red ──> Blue ──[not converged AND round < cap]──> Red   (loop back)
                             └─[converged OR round >= cap]───────> Reporter ──> output, halt
```

**Why a cyclic graph rather than a linear chain.** The framework offers
`SequentialWorkflowBuilder`, which would run Red→Blue→Reporter exactly once. That satisfies
AC1 but makes AC3 meaningless: a single pass cannot exceed a turn-cap. AID-01 §3.1
describes a *debate* — Red asserts, Blue rebuts, and the exchange continues until Blue
cannot break a link. That requires a loop, so the graph is built explicitly with
`WorkflowBuilder` and a Blue→Red back edge.

**Why both exits land on the Reporter.** AC3 requires that a turn-capped run still produce
Reporter output. Two conditional edges leave Blue, and their predicates are complements:

```csharp
.AddEdge(blueNode, redNode,      (DebateTurn t) => !t.Converged && t.Round < maxRounds)
.AddEdge(blueNode, reporterNode, (DebateTurn t) =>  t.Converged || t.Round >= maxRounds)
```

Because the two conditions partition every possible state, there is no path out of Blue
that skips the Reporter. AC3 holds by construction rather than by a special case that
someone could later delete. This is deliberate: a guarantee expressed in graph topology
survives refactoring better than one expressed in a conditional inside an agent.

**Why the predicates read only the message.** Both conditions are pure functions of the
`DebateTurn` flowing along the edge. They do not consult shared state, so routing stays
deterministic and cannot disagree with what the agents recorded.

### 3.2 The Orchestrator is a graph, not a class with a loop

AID-01 §3.1 describes the Orchestrator as sequencing turns, enforcing the turn-cap,
detecting convergence, and routing model tier — explicitly asserting nothing about security
itself.

Those responsibilities are split by where they belong:

| Responsibility | Where it lives | Why |
|---|---|---|
| Sequencing turns | Graph edges | The framework's scheduler already does this correctly, including across a resume |
| Turn-cap | Conditional edge predicate | Termination becomes a topological property, not a runtime check that can be bypassed |
| Convergence detection | `BlueTeamExecutor` sets `Converged` | Only Blue knows whether a link broke |
| Model-tier routing | `DebateOptions.Tiers` → `IChatClientFactory` | Config, resolved once at build time |
| Seeding the debate | `OrchestratorExecutor` | Needs to run before Red and initialise shared state |

`OrchestratorExecutor` is therefore small: it writes an empty `DebateState` and emits the
opening brief. It is the entry node, not a controller.

### 3.3 Agents are real agents; only the connector is stubbed

This is the most consequential decision in the build.

SEC-02 says "three **stub** agents". The naive reading is three classes that return canned
strings. That reading was rejected because it would have to be thrown away the moment a
real model was connected — the stub classes would be replaced wholesale, and none of the
orchestration, state, or checkpoint behaviour proven in Sprint 1 would have been exercised
against the code path that ships.

Instead, Red, Blue and Reporter are genuine `ChatClientAgent` instances in **every**
configuration. The stubbing happens one layer lower, at the `IChatClient` seam:

```
RedTeamExecutor ─> ChatClientAgent ─> IChatClient ─┬─> ScriptedChatClient  (tests, offline)
                                                    ├─> OpenAI client → NIM
                                                    ├─> OpenAI client → Anthropic
                                                    └─> OpenAI client → Azure OpenAI
```

Consequences, all of them intended:

- The code path under test in Sprint 1 is the code path that runs in the demo. Only the
  transport changes.
- AID-01 §2's claim — *"the model sits behind the connector abstraction, so switching
  provider is a config change, proven by an integration test"* — becomes literally true and
  is asserted by `ProviderSwitchTests`.
- The tests run with no API key, no network, and no token spend, while still driving real
  agent machinery.

This also directly serves the project's stated model plan: NVIDIA NIM is available now,
Claude access is expected later. NIM speaks the OpenAI wire format, so it reuses the OpenAI
client with a base-URL override. Moving to Claude is `"Provider": "Anthropic"` plus a key.
Had the agents been hand-written stub classes, that migration would have been a rewrite.

### 3.4 Shared session state

All three agents read and write one record under a shared scope:

```csharp
public const string StateKey    = "sentinel.debate.state";
public const string SharedScope = "sentinel.debate";
```

`DebateState.Transcript` is append-only; `DebateState.Append` returns a new record rather
than mutating, so a turn cannot be lost to a partially-applied update.

**Why go through `IWorkflowContext` rather than a field.** This is what makes AC2 work.
The framework snapshots context state after every superstep. A resumed run restores that
snapshot, so completed turns are *present in state* without being *re-executed*. State held
in executor fields would survive within a process but would be invisible to the
checkpointer — the resume would silently re-run work and the transcript would double.

### 3.5 Join confidence

AID-01 §3.3 requires that a chain inherit its weakest edge's confidence, so one unresolved
hop marks the whole chain for human review. The enum is ordered to make that a one-liner:

```csharp
public enum JoinConfidence { Unresolved = 0, Inferred = 1, Certain = 2 }
...
WeakestJoin = state.Transcript.Min(t => t.Confidence)
```

Ordering the enum weakest-first means `Min()` *is* the "weakest link" rule. The alternative
— a hand-written comparison — would be a place for the precedence to drift away from the
design document.

An unresolved join never silently kills a chain. `DraftAudit` still reports it, carrying
`WeakestJoin = Unresolved`, per AID-01 §7's requirement that such chains surface as
"potential chain, unverified join". `DraftAudit.Disclaimer` hard-codes the
draft-for-human-review framing so it cannot be omitted by a caller.

---

## 4. Problems encountered and what they changed

Five defects surfaced during the build. All were caught by compiling and running rather
than by review, and each changed the design. The fifth (§4.5) is the most instructive: it
passed all 18 tests and was only exposed by running the demo.

### 4.1 Output type validation

```
InvalidOperationException: Cannot output object of type DraftAudit.
Expecting one of [SentinelAI.Agents.Contracts.DebateTurn].
```

The framework derives an executor's legal output types from its declared generic
parameter. `ReporterExecutor` inherited `Executor<DebateTurn, DebateTurn>`, so it could
only ever yield a `DebateTurn` — but the Reporter's product is a `DraftAudit`.

**Fix.** The shared base became `DebateExecutor<TOutput> : Executor<DebateTurn, TOutput>`,
with a non-generic `DebateExecutor : DebateExecutor<DebateTurn>` convenience subclass for
Red and Blue. The Reporter closes the generic on `DraftAudit`.

**Why this is better than the workaround.** Suppressing the validation would have hidden a
genuine asymmetry: the Reporter is the only terminal node, and it is the only one whose
output is not another debate turn. Encoding that in the type system means the graph cannot
be miswired to route a `DraftAudit` back into Red.

### 4.2 Workflow ownership

```
InvalidOperationException: Cannot use a Workflow that is already owned by
another runner or parent workflow.
```

A `Workflow` may be owned by one runner at a time. The failed first run still held
ownership, so the resume could not claim it — which meant AC2 was untestable.

**Fix.** `DebateRunner` now disposes each run before returning (`await using var run`).

**Why it matters beyond the test.** This is the real production path: a crashed run must
release its workflow before a recovery run can start. The test surfaced a genuine
lifecycle bug, not a test artifact.

### 4.3 Argument evaluation order masking a configuration error

The first `ChatClientFactory` dispatched like this:

```csharp
ModelProvider.AzureOpenAI => OpenAICompatible(tier, RequireEndpoint()),
```

C# evaluates arguments before entering the method, so `RequireEndpoint()` threw first. An
Azure configuration missing *both* endpoint and key reported only the missing endpoint —
the operator would fix it and immediately hit a second, different error.

**Fix.** Credentials are validated first, inside the method, for every live provider;
endpoint resolution moved into `DefaultEndpointFor`.

**Why.** Diagnostics should report the most fundamental missing item first, and should be
consistent across providers. A misconfigured provider now always says "needs an API key",
whichever provider it is.

### 4.4 Leaked file handle in the checkpoint helper

The first disk-checkpoint helper returned a `CheckpointManager` and dropped the underlying
`FileSystemJsonCheckpointStore` on the floor. The store holds `index.jsonl` open, so the
directory could never be released — the test's cleanup failed with a sharing violation.

**Fix.** The API was made honest about ownership:

```csharp
public static FileSystemJsonCheckpointStore OpenFileStore(string directory);
public static CheckpointManager Persistent(FileSystemJsonCheckpointStore store);
```

The caller now holds the disposable and can close it.

**Why this improved the test too.** Disposing the store between the two runs is precisely
what a process restart does. The test went from "same object, replayed" to a genuine
close-and-reopen against the same directory — a materially stronger assertion.

---

### 4.5 Role inference that silently matched nothing

`ScriptedChatClient` originally inferred which agent was calling by searching the incoming
messages for a `System` message containing "Red Team", "Blue Team" or "Reporter".

Running the demo for the first time showed all three agents returning the fallback string
`"SCRIPTED: no role matched."`, and a debate that never converged. A probe confirmed why:

```
MSG role=user text=hello
OPTIONS.Instructions = You are the Red Team agent.
```

`ChatClientAgent` passes agent instructions via `ChatOptions.Instructions`, **not** as a
`System` message. The sniffing looked somewhere the data never was.

**Why the test suite missed it.** `TestDebate` injects an explicit responder per role, so
every acceptance test overrode the default script. The broken path was real product code
that no test ever executed — 18 passing tests, and a demo that produced nonsense.

**Fix.** The guessing was removed rather than corrected. `IChatClientFactory.Create` now
takes the `AgentRole` explicitly:

```csharp
IChatClient Create(AgentRole role, ModelTier tier);
```

The factory already routed model *tier* per role, so it always had the role available —
the original signature simply discarded it. Offline providers now answer in character
because they are told who they are, and the same parameter gives live providers a place to
route roles to different models later.

**What it changed about testing.** Two regression tests now cover the previously untested
default path: `The_scripted_client_answers_in_character_for_each_role` asserts Red/Blue/
Reporter produce ASSERT/VALIDATE/ADJUDICATE respectively, and `Every_debate_role_has_a_canned_turn`
walks the enum so a newly added role cannot silently fall through.

**The wider lesson for the sprint.** A test suite that stubs a seam thoroughly can leave
the real implementation of that seam completely unexercised. This is the argument for the
demo runner existing at all — it is the only thing that ran the default configuration
end to end, and it found the bug immediately.

---

## 5. Testing

18 tests, all offline against `ScriptedChatClient`.

### 5.1 How the acceptance criteria are proven

| AC | Test | What actually makes it convincing |
|----|------|-----------------------------------|
| AC1 | `Agents_run_in_order_sharing_session_state` | Asserts the transcript is exactly `[Red, Blue, Reporter]` **and** that the Reporter's audit contains Red's and Blue's content — which the Reporter never received directly. Only shared state can explain that. |
| AC2 | `Resuming_after_a_mid_run_failure_does_not_rerun_completed_turns` | Asserts the Red agent's chat client was invoked **exactly once across both attempts**. If resume re-ran completed turns the count would be 2. |
| AC3 | `Turn_cap_terminates_the_debate_and_the_reporter_still_outputs` | Blue is scripted never to converge, so only the cap can stop the run. Asserts no exception, an audit exists, `TerminatedByTurnCap` is true, and exactly `MaxRounds` Red/Blue exchanges occurred. |

### 5.2 Why per-role scripted clients

`TestDebate` wires a separate `ScriptedChatClient` to each of the three agents. Call counts
are therefore attributable to a specific agent. This is what makes AC2 a real assertion:
"Red ran once" is only meaningful if Red's invocations can be distinguished from Blue's.

### 5.3 Failure injection

AC2 needs a mid-run failure. Blue's scripted responder throws on its first invocation and
succeeds thereafter:

```csharp
Interlocked.Exchange(ref blueShouldFail, 0) == 1
    ? throw new InvalidOperationException("Blue crashed mid-debate.")
    : TestDebate.Converges
```

Injecting the fault at the connector rather than inside the executor keeps the production
code free of test hooks. The failure is indistinguishable from a real model call failing.

The distinction the test encodes: **Red ran once (not re-run), Blue ran twice (retried).**
Re-running completed work is the bug; retrying the step that failed is correct behaviour.

### 5.4 Coverage beyond the three criteria

- `Turn_cap_of_one_still_reaches_the_reporter` — boundary case, `MaxRounds = 1`.
- `Turn_cap_below_one_is_rejected` — `DebateOptions.Validate` rejects a cap that permits no
  rounds, rather than building a graph that can never reach the Reporter.
- `Chain_inherits_the_weakest_join_confidence` / `Unresolved_join_is_surfaced_not_dropped` —
  AID-01 §3.3 and §7 invariants.
- `A_completed_run_writes_checkpoints`, `Checkpoints_survive_a_process_restart_on_disk`.
- `ProviderSwitchTests` — provider switching, fail-loud on missing credentials, per-provider
  model-tier defaults, explicit model override.

---

## 6. Configuration

```jsonc
{
  "SentinelAI": {
    "Models": {
      "Provider": "Nim",              // Scripted | Nim | Anthropic | AzureOpenAI
      "ApiKey": "<supply via environment or user-secrets>",
      "HighTierModel": "meta/llama-3.3-70b-instruct",
      "CheapTierModel": "meta/llama-3.1-8b-instruct"
    },
    "Debate": { "MaxRounds": 3 }
  }
}
```

`Scripted` is the default, so an unconfigured checkout runs green with no credentials.

**Fail-loud on missing credentials.** Every live provider throws if no key is supplied. It
never falls back to the scripted client. This mirrors the same-model invariant guard in
AID-01 §5 — where a silent 512-dim bag-of-words fallback during the POC is the exact
failure that guard was written to prevent. A silent fallback to stub responses would be the
same class of bug: a run that looks successful and means nothing.

**Model-tier routing** (AID-01 §2.1) is configured per role. All three default to the high
tier because chaining, link validation and adjudication are all reasoning-heavy turns; the
cheap tier is wired and available for routine formatting work added later.

---

## 7. Scope boundaries

Deliberately **not** implemented, because SEC-02 is the skeleton:

- No retrieval — no Qdrant, no offence/defence collections, no decision tree (SEC-06→09).
- No real resource graph — `ScanBrief` is a stub string that becomes normalized findings
  plus the graph in a later story (SEC-08).
- No real prompts — agent instructions are written to the design document's description of
  each role, but the responses are scripted.
- No full SEC-03 contract set — `Finding`, `Node`, `Edge`, `Chain` are out of scope here;
  only the debate-local contracts exist. SEC-03 is owned separately.
- No API surface, persistence, or telemetry — SEC-01, SEC-05 and SEC-37.

Two known gaps that belong to SEC-01 (Member F) rather than this story: `AgentsProject` is
not yet a git repository, and there is no CI workflow.

---

## 8. Summary of decisions

| Decision | Alternative rejected | Reason |
|---|---|---|
| Pin MAF 1.15.0 | Chase a literal "1.0" | 1.15.0 is the shipping 1.x GA line the docs mean |
| Verify API by reflection dump | Write from documentation/recall | Fast-moving 1.x library; three assumptions would have been wrong |
| Explicit cyclic `WorkflowBuilder` graph | `SequentialWorkflowBuilder` | A single pass cannot exercise a turn-cap; AID-01 describes a debate, not a pipeline |
| Complementary conditional edges out of Blue | Reporter-runs-anyway special case | Makes AC3 a topological guarantee rather than a deletable branch |
| Real `ChatClientAgent`s, stub at `IChatClient` | Hand-written stub agent classes | Same code path in test and demo; makes the provider switch a config change; NIM→Claude needs no rewrite |
| State via `IWorkflowContext` | Executor instance fields | Only context state is checkpointed; fields would break resume silently |
| `JoinConfidence` ordered weakest-first | Hand-written comparison | `Min()` becomes the weakest-link rule, so it cannot drift from AID-01 §3.3 |
| Framework-native checkpointing | Hand-rolled serialization | Already provided per superstep; hand-rolling duplicates and diverges |
| Caller owns the checkpoint store | Helper hides the disposable | Leaked the index file handle; explicit ownership also enables a true restart test |
| Fail loud on missing credentials | Fall back to scripted | A silent fallback produces runs that look successful and mean nothing |
| Pass `AgentRole` to the factory | Infer the role from the prompt text | Sniffing matched nothing (instructions travel in `ChatOptions.Instructions`); the factory already had the role and was discarding it |
| Ship a demo runner | Tests only | Tests stubbed the connector so thoroughly that its real implementation was never executed; the demo found that bug on first run |

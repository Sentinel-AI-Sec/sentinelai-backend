# Understanding this project from zero

A ground-up explanation for someone who has never worked with AI agents.

No prior knowledge assumed. If you know what an LLM is, skim §1. If you know what an agent
is, start at §4.

---

## 1. The starting point: a model is a text function

A large language model (LLM) — GPT-4o, Claude, Llama, NVIDIA's Nemotron — does exactly one
thing:

> You give it text. It gives you back text that plausibly continues it.

That is the whole primitive. Everything else is built on top.

Two consequences drive this project's entire design:

**It has no memory.** Each call is independent. Ask a question, get an answer, ask a
follow-up — the model has already forgotten the first exchange. If it appears to remember,
that is because the program re-sent the earlier conversation as part of the new request.
Memory is something *you* build, not something the model has.

**It cannot verify anything.** It produces text that *reads* like a correct answer. For
security work this is the central problem: ask a model "find attack paths in this system"
and it will confidently produce attack paths, including ones that do not exist. They will be
well-written and plausible. That failure mode is called **hallucination**, and everything in
§4 exists to fight it.

---

## 2. What an "agent" actually is

An **agent** is a model call plus three additions:

| Ingredient | What it means here |
|---|---|
| **Instructions** | A fixed briefing prepended to every call — its job description. |
| **A narrow job** | One responsibility, not "be helpful". |
| **A place to put results** | Somewhere its output is stored so other agents can use it. |

That is genuinely it. An agent is not a running process, not a background service, not a
robot. In our code an agent is one object, `ChatClientAgent`, holding an instruction string
and a connection to a model.

Here is our Blue agent's actual briefing, shortened:

> *You are the Blue Team agent. Validate every hop of the asserted chain against the real
> configuration. Mark any hop you cannot confirm with the word UNRESOLVED. End with
> `VERDICT: CHAIN_HOLDS` or `VERDICT: CHAIN_BROKEN`.*

Same underlying model as the other agents. Different briefing. That difference is the whole
of what makes it "the Blue agent".

> **The one-sentence version:** an agent is a model given a job description and a place to
> write its answer.

---

## 3. What SentinelAI is trying to do

SentinelAI scans a codebase for security problems. Existing scanners already find isolated
issues:

- A **code** scanner: *"this function unsafely deserializes untrusted input"*
- A **dependency** scanner: *"this library version has a known vulnerability"*
- An **infrastructure** scanner: *"this cloud IAM role grants overly broad permissions"*

Each alone is a low-priority warning. The project's thesis is that the danger lives in how
they **chain together across layers**:

```
vulnerable library  →  the code that calls it  →  the container running that code
                    →  the IAM role that container assumes  →  the S3 bucket holding PII
```

Five individually-unremarkable findings compose into one path from "attacker sends bad data"
to "attacker reads your customer data". Finding those chains is what this project calls
**cross-layer exploit-path reasoning**, and it is what the agents are for.

---

## 4. Why four agents instead of one

The obvious approach — hand everything to one model and ask for attack paths — fails for
the reason in §1: a single model asked to find attack chains invents plausible ones.

So the design makes the agents **argue**.

| Agent | Job | Analogy |
|---|---|---|
| **Orchestrator** | Runs the session. Decides who speaks, when to stop. Asserts nothing about security. | The chairperson |
| **Red Team** | Claims an attack chain exists, hop by hop. | The prosecutor |
| **Blue Team** | Checks each hop against the real configuration. One broken link kills the chain. | The defence |
| **Reporter** | Reads the argument and writes the final ranked report. | The judge |

The insight: **a claim survives only if it withstands a dedicated opponent.** Red is
motivated to assert; Blue is motivated to demolish. A chain that survives Blue is
substantially more trustworthy than a chain one model produced unopposed.

This is why the project's own documents call the debate *"the source of grounded,
low-false-positive findings"*.

---

## 5. Vocabulary

The terms you need to read anything else in this repo.

**Turn** — one agent speaking once. Red asserting a chain is one turn.

**Round** — one full Red→Blue exchange. Round 2 means they have each spoken twice.

**Session state** — the shared notebook. Every agent writes its turn into it and can read
everything written before. This is the memory the model does not have (§1). In our code:
`DebateState`, holding the running `Transcript`.

**Turn-cap** — a hard limit on rounds. Red and Blue could disagree forever; the cap forces
the Reporter to write the report regardless. Ours defaults to 3. Without it, a stubborn
disagreement is an infinite loop that bills you per iteration.

**Convergence** — the debate ending naturally because Blue could not break the chain. The
good ending, as opposed to hitting the turn-cap.

**Checkpoint** — a saved snapshot of the session state, written after every step. If the
program crashes on turn 4, it restarts from the checkpoint rather than re-running turns 1–3.
Model calls cost money and take ~10–50 seconds each, so not repeating them matters.

**Workflow** — the map of who hands off to whom. Ours:

```
Orchestrator ──> Red ──> Blue ──[chain broken, rounds left]──> Red      (argue again)
                             └─[chain holds, or cap reached]──> Reporter (write it up)
```

**Executor** — one node in that map. `RedTeamExecutor` is the box labelled "Red".

**Provider / connector** — which company's model is actually answering. NVIDIA NIM,
Anthropic, Azure OpenAI, or our fake offline one. Swapping it is a config change; no agent
code changes.

**Hop** — one link in an attack chain. `N1→N2` is a hop.

**Join confidence** — how sure we are that a hop is real:

| Tier | Meaning |
|---|---|
| `Certain` | Confirmed from an authoritative source (a lock file, an IAM policy) |
| `Inferred` | Matched by convention, e.g. two places using the same image name |
| `Unresolved` | Could not confirm it either way |

A chain is only as trustworthy as its weakest hop, so one `Unresolved` hop marks the whole
chain for human review. It is **not** discarded — an unconfirmed link is not a disproven
one.

---

## 6. A real run, narrated

This is genuine output from a live run against NVIDIA's 550-billion-parameter Nemotron
model, with commentary.

### Setup

The agents receive a small resource graph — five nodes, four edges:

```
N1 = pkg:commons-collections:3.2.1     (a library with a known CVE)
N2 = code:AppDataHandler.deserialize() (code that unsafely deserializes)
N3 = infra:ecs-task/api-service        (the container running it)
N4 = iam-role:api-task-role            (the cloud role it assumes)
N5 = s3:customer-data-bucket(PII)      (the bucket holding customer data)
```

One edge is deliberately marked `INFERRED` — the N2→N3 link is guessed from a matching
container image name, which is a convention, not a proof. Watch what the agents do with it.

### Round 1 — Red asserts *(25.9 s)*

```
N1 → N2: gadget-chain deserialization via InvokerTransformer — lock file pins 3.2.1
N2 → N3: container deployment of vulnerable deserializer — base-image:latest (INFERRED)
N3 → N4: task-role assumption at runtime — task def taskRoleArn → api-task-role
N4 → N5: S3 object write/read with task credentials — IAM policy grants s3:Get/PutObject
```

Red built the full five-node chain, cited evidence per hop, and flagged the weak link
itself. It used only edges that exist in the supplied graph — it did not invent one.

### Round 1 — Blue validates *(9.0 s)*

```
N1 → N2: VALIDATED — lock file pins 3.2.1, code imports InvokerTransformer
N2 → N3: UNRESOLVED — INFERRED image-name join is convention-dependent
N3 → N4: VALIDATED — task def taskRoleArn → api-task-role
N4 → N5: VALIDATED — IAM policy grants s3:Get/PutObject
VERDICT: CHAIN_BROKEN
```

Blue checked each hop independently and correctly isolated the single unconfirmable one.
Its discrimination is exactly right.

**But the verdict is wrong**, and this is worth understanding. Blue did not *refute*
anything. It could not *confirm* one hop. Per the design, unconfirmable means the chain
survives carrying an `Unresolved` flag — it does not mean broken. Blue conflated *"I cannot
verify this"* with *"this is false"*. Those are different claims, and treating them the same
throws away a real finding.

This is a genuine open defect, documented in
[Live_Model_Findings.md §5](Live_Model_Findings.md).

### Rounds 2 and 3 — the consequence

Because Blue said "broken", the Orchestrator sent it back to Red. Red re-asserted
essentially the same chain; Blue reached the same conclusion. Twice more.

The turn-cap then did its job: at round 3 the Orchestrator stopped the argument and routed
to the Reporter — exactly the runaway-loop protection §5 describes, doing real work.

### The Reporter adjudicates *(10.9 s)*

```
1. Confirmed — Critical deserialization gadget: commons-collections:3.2.1
   (CVE-2015-6420, CVSS 9.8) [F1, F2, N1→N2 confirmed]
2. Confirmed — Overprivileged task role: api-task-role with s3:Get/PutObject
   on customer-data-bucket (PII) [N3→N4, N4→N5 confirmed]
3. Potential chain, unverified join: if AppDataHandler runs in api-service
   (N2→N3 inferred, not verified), attacker-controlled S3 blob → RCE → PII
   exfiltration [N2→N3 unresolved]
4. Exploitability ranking: gadget reachable in code > IAM overprivilege > full
   chain contingent on unverified join
```

This is the behaviour the design asks for. The Reporter separated what is confirmed from
what is contingent, ranked by exploitability, and labelled the weak chain *"potential chain,
unverified join"* rather than asserting or discarding it — despite Blue having called it
broken.

### Outcome

```
rounds            : 3
turns             : 7
outcome           : stopped by turn-cap
weakest join      : Unresolved
checkpoints       : 8
elapsed           : 133.7s
```

**One honest caveat.** Those `[F1, F2, N1→N2 confirmed]` markers look like citations, but
they are echoes of what the prompt already contained — not references to retrieved security
knowledge. Real citation against a knowledge base is a later story. Grounding today means
*grounded in the prompt*, which is a weaker claim and should be described as such.

---

## 7. Where each concept lives in the code

```
src/SentinelAI.Agents/
  Contracts/      DebateTurn      — one agent speaking once
                  DebateState     — the shared notebook (§5)
                  DraftAudit      — the Reporter's final output
                  JoinConfidence  — Certain / Inferred / Unresolved

  Providers/      ChatClientFactory   — picks NIM / Anthropic / Azure / offline
                  ScriptedChatClient  — the fake model used by every test

  Executors/      OrchestratorExecutor — starts the session
                  RedTeamExecutor      — asserts chains
                  BlueTeamExecutor     — validates hops
                  ReporterExecutor     — writes the audit

  Orchestration/  DebateWorkflow  — the map in §5
                  DebateRunner    — runs it, saves checkpoints, resumes
                  DebateOptions   — the turn-cap and other knobs
```

### The one design decision worth understanding

The tests never call a real model. They use `ScriptedChatClient`, a fake that returns fixed
text instantly, free, offline.

But the agents are **not** faked. They are the same real agent objects, running the same
real workflow, with the same real state and checkpointing. Only the thing at the far end of
the wire is swapped:

```
RedTeamExecutor → ChatClientAgent → IChatClient → ┬─ ScriptedChatClient (tests)
                                                  ├─ NVIDIA NIM        (demo)
                                                  └─ Anthropic         (later)
```

Why it matters: the code exercised by the tests is the code that runs in production. And
moving from NIM to Claude is editing a config value — no agent code changes. That property
is asserted by its own tests.

---

## 8. Try it yourself

Offline. No API key, no network, no cost, finishes in about a second:

```bash
dotnet run --project samples/SentinelAI.Agents.Demo -- debate
```

Then the other scenarios:

```bash
dotnet run --project samples/SentinelAI.Agents.Demo -- turncap
```

```bash
dotnet run --project samples/SentinelAI.Agents.Demo -- resume
```

`turncap` shows the argument being stopped by the cap. `resume` kills the run mid-debate and
restarts it from a checkpoint — watch it *not* redo the completed turns.

Run the test suite:

```bash
dotnet test
```

To use a real model instead, see [Configuration.md](Configuration.md). Expect 90–140
seconds and roughly 10–50 seconds of silence per turn while a model thinks.

---

## 9. What is not built yet

So you can tell demonstrated capability from planned capability:

- **No knowledge base.** The agents do not look anything up. No CVE database, no ATT&CK
  techniques. That is a separate story.
- **No real graph.** The five nodes in §6 are a hand-written fixture, not extracted from a
  real repository.
- **No scanners.** Nothing actually scans code yet. The findings are written into the
  fixture.
- **Real citations.** See the caveat in §6.
- **Blue's UNRESOLVED handling.** The open defect in §6.

What *is* built and proven: the debate structure, shared memory, checkpoint-and-resume,
guaranteed termination, provider portability, and per-agent credentials.

---

## 10. Where to go next

| Question | Document |
|---|---|
| How do I configure providers and keys? | [Configuration.md](Configuration.md) |
| Why is the code shaped this way? | [SEC-02_Design_Notes.md](SEC-02_Design_Notes.md) |
| What broke against real models? | [Live_Model_Findings.md](Live_Model_Findings.md) |
| How does the real graph plug in? | [Graph_Integration.md](Graph_Integration.md) |

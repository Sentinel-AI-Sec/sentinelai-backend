# LLM tracing (SEC-36)

**Code:** `src/SentinelAI.Infrastructure/Observability/`
**Tests:** `tests/SentinelAI.Integration.Tests/Agents/DebateTracingTests.cs` (7),
`tests/SentinelAI.Infrastructure.Tests/Security/TelemetryEgressTests.cs` (11)
**Backend:** any OTLP collector. Langfuse is the one the ticket names and the one the
configuration has a shortcut for.

---

## What is captured

One span per agent turn, nested inside one span per debate.

```
debate                        sentinelai.scan_job_id, turns, converged
├── debate.turn Orchestrator  round 0 — the brief
├── debate.turn Red           round 1
├── debate.turn Blue          round 1
├── debate.turn Red           round 2
├── debate.turn Blue          round 2
└── debate.turn Reporter      round 2 — adjudication
```

Each turn span carries:

| Attribute | Meaning |
|---|---|
| `gen_ai.usage.input_tokens` / `output_tokens` | What the provider billed |
| `gen_ai.response.model` | Which model answered, when the provider says |
| `gen_ai.response.finish_reasons` | Why it stopped — a truncated turn shows up here |
| `sentinelai.agent.role` | Orchestrator / Red / Blue / Reporter |
| `sentinelai.debate.round` | Taken from the turn, not from the one before it — see below |
| `sentinelai.model.tier` | SEC-31's routing decision, as it actually ran |
| `sentinelai.debate.converged`, `…verdict_readable` | Why the debate looped again, or stopped |
| `sentinelai.trace.content_captured` | Whether this span was permitted to carry text |
| `gen_ai.prompt`, `gen_ai.completion` | Only when content capture is on |

Latency is the span's own duration. There is no separate stopwatch, because a second number can
disagree with the first.

The `gen_ai.*` names follow the OpenTelemetry semantic conventions for generative AI, which is
what makes Langfuse render these as model calls rather than as anonymous spans.

## Turning it on

```jsonc
"Observability": {
  "Tracing": {
    "OtlpEndpoint": "https://cloud.langfuse.com/api/public/otel/v1/traces",
    "ServiceName": "sentinelai-backend",
    "CaptureContent": false,
    "Langfuse": { "PublicKey": "pk-lf-…", "SecretKey": "" }
  }
}
```

`SecretKey` is a credential. Supply it from the environment
(`Observability__Tracing__Langfuse__SecretKey`) or from Key Vault — never from a committed file.
The CI secret-hygiene job will not catch it for you: it looks for provider key prefixes, and
Langfuse's are not on that list.

**Empty `OtlpEndpoint` is off, and off is a complete no-op.** No exporter is registered, no
listener subscribes, `ActivitySource.StartActivity` returns null, and the instrumentation costs
one null check per turn. The prompt is never read. That is the same argument as the `Scripted`
provider default: a fresh clone and a CI run must work with no credentials and no collector.

HTTP/protobuf, not gRPC — Langfuse's OTLP ingest is HTTP-only, and the endpoint you are given is
a full `/v1/traces` path. Pointing a gRPC exporter at it fails at connect time with an error that
reads like a network problem rather than a protocol mismatch.

## Replay

SEC-36 asks for "full debate replay from the trace". `DebateTraceReplay` is the reader:

```csharp
var replay = DebateTraceReplay.From(spans);

Console.WriteLine(replay.ToTranscript());
// debate 01a019ee-… — 6 turn(s), 4120 in / 890 out, 12.4s in model calls
//
// ── Red · round 1 · High · 780 in / 210 out · 3.10s · deepseek-r1
//    PROMPT: …
//    ANSWER: …
```

It re-reads what each agent was asked and what it answered, in order, with the tokens and latency
each turn cost. It does not re-execute anything — the models are not deterministic and a trace is
not a recording. What a person debugging a bad audit needs is the first thing.

**Why a reader exists when Langfuse already renders spans:** because a claim that a debate is
replayable is worth what the thing checking it is worth. `A_captured_debate_replays_into_the_transcript_it_produced`
runs a real debate over the scripted provider, collects its spans in-process, replays them, and
compares the result to the transcript the debate itself produced. A replay that lost a turn,
reordered two, or attributed one to the wrong agent fails there.

**The transcript prints the prompt as well as the answer.** A transcript of answers alone reads
plausibly and hides the usual cause of a bad turn, which is that the agent was asked the wrong
thing — Blue opening with *"the user is asking me to act as the Red Team agent"* was diagnosed
exactly this way.

### One bug this already caught

The first version stamped the span with the *incoming* turn's round. That is right for Blue and
the Reporter, which answer within the round they were handed, and wrong for Red, which opens a
new one — so every Red turn appeared in the trace one round early. Nothing about the span looked
wrong; the replay test failed because the transcript it rebuilt did not match the one the debate
produced.

The fix is that the round is set from the turn the executor produces, after the model has
answered (`DebateTracing.RecordTurn`). The span therefore opens before the call and closes after
interpretation, and its duration is the whole turn rather than only the request.

## Content capture is a security decision, not a verbosity setting

`CaptureContent` defaults to **false**, and it has its own switch rather than riding on
`OtlpEndpoint`.

With it off, a trace carries token counts, a tier, a latency and a role name — nothing of the
customer's. With it on, the trace also carries the prompts and the answers, which means **the
collector becomes a second destination for job content**, alongside the model provider. A
customer who accepted that their infrastructure description goes to an LLM vendor did not thereby
accept that it also goes to an observability vendor.

So it goes in front of the same check the provider endpoint passes (SEC-34):

- `EgressPurpose.Telemetry` is a third purpose on the egress policy.
- `ConfiguredOutboundEndpoints` reports the OTLP endpoint **only when `CaptureContent` is true**.
  Metadata-only tracing is not job-content egress and is not reported — requiring an allowlist
  entry for a token count would push operators to leave observability off, or to add a blanket
  host and mean nothing by it.
- There is **no compiled-in telemetry host**, deliberately, exactly as there is none for the
  vector store and for the same reason: there is no vendor. A collector is wherever the
  deployment put it.

The consequence is the one that makes the decision deliberate:

> Switching `CaptureContent` on without naming the collector in
> `Security:Egress:TelemetryHosts` refuses every scan job with a 503 naming the setting.

```jsonc
"Security": {
  "Egress": {
    "TelemetryHosts": [ "cloud.langfuse.com" ]
  }
}
```

Langfuse Cloud is `cloud.langfuse.com` or `us.cloud.langfuse.com`. A self-hosted collector obeys
the same transport rule as everything else on the allowlist — **https, or loopback** — because
sending prompts in the clear to an internal collector still puts them on somebody's network.

### What is already redacted before a span sees it

`RedactingDebateEngine` scans the brief for secrets on its way to the model, and the SEC-33
ingress gate has already cleaned everything the bundle contributed. Prompts are built from the
redacted brief, so a captured prompt has been through both. That is a reason the exposure is
bounded, **not** a reason it is nil: the destination is still a third party, and that is what the
allowlist entry is for.

## Cost, and what is not covered

Traces only. Metrics and logs are a different ticket and a different backend concern; exporting
three signals to an endpoint sized for one because the package supports it would be a change
nobody asked for.

The Agent Framework's own sources (`Microsoft.Agents.AI`, `Microsoft.Extensions.AI`) are
subscribed alongside ours. They emit only when a chat client is wrapped in the framework's
OpenTelemetry decorator, which this project does not do — so today they produce nothing. They are
subscribed anyway because the cost is zero and the alternative is a deployment that turns the
decorator on later and silently exports nothing while believing it is instrumented.

**Every model call is traced through one of two call sites** — `DebateExecutor.RunTurnAsync` for
Red, Blue and the Reporter, and `OrchestratorExecutor.HandleAsync` for the seed. Both go through
`DebateTracing`, which is the same argument that put tier and usage stamping in one place: a new
agent cannot be added that spends tokens nobody traced.

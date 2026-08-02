

```

 This sprint I took SEC-02, the agent orchestration skeleton. It was flagged as the project's
 top technical risk, so it got built first.


 It's the debate engine. Four agents on Microsoft Agent Framework. An Orchestrator reads the
 resource graph and briefs the team. Red asserts a cross-layer attack chain. Blue tries to
 break every hop. The Reporter writes up whatever survived. They all share one session state,
 so every agent sees the full transcript.


 Two guarantees were the real work. The debate always terminates — the turn-cap is built into
 the shape of the workflow graph, not a loop counter someone has to remember to check. And it
 resumes from a checkpoint without re-running completed turns. I prove that on call counts,
 not on output.


 Then SEC-30, the provider abstraction. The model sits behind one interface, so switching
 providers is a config change, not a rewrite. I ran the full debate live on NVIDIA NIM —
 with four separate API keys, one per agent, so one agent can't burn through another's
 rate limit.


 Seventy-three tests, all offline. No keys, no cost, no network.
```
---

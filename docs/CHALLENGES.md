# Challenges faced

What got in the way on 10 October 2026 and what we did about it.

## What existed before the event, and what was built today

To be transparent: the harness (agent loop, stub tools, local policy stand-in, signed record, `verify.py`, replay and diff) was scaffolded before hacking started, from public material only. Everything that touches a live AgntID runtime was built on the day: running the runtime, the portal configuration, the `payments` and `comms` MCP servers, the agent team for the bank incident, the AgntID adapter running against a real runtime, the attack suite, the voice on-call call, the policy writer, the CI gate, the evidence pack and the runtime proof script. `git log` shows the split.

## 1. First contact with a live runtime

The AgntID adapter (`cleargate/agntid_enforcer.py`) was written against the public SDK before the event and had never run against a runtime. The first hours went into the real flow end to end: bootstrap token, control-plane connection, MCP servers discovered, task open, delegation open, wrapped calls, denial parsing. Features waited until that worked.

## 2. Tool names change behind the runtime

The runtime exposes tools as `<server>_<tool>`, with dots turned into underscores. ClearGate's policy, agents and record used `server.tool`. We added one mapping (`AgntIDEnforcer.runtime_name`, and `runtime_name` / `from_runtime_name` in `cleargate/tools/base.py`) so every part of ClearGate agrees with the runtime.

## 3. No policy API

Policies are created in the portal's visual editor. We could not version them in the repo and apply them from code. `docs/AGNTID_IMPLEMENTATION.md` is the source of truth, the portal is configured by hand from it, and `policy.yaml` mirrors it for the offline stand-in. Keeping the two in sync is manual.

## 4. Approval is not an AgntID primitive

The runtime allows or denies; it does not hold a pending human approval. We built the escalation in ClearGate: the runtime denies the merge, ClearGate binds a human approval to the SHA-256 digest of the exact arguments, then re-sends the call with the evidence. A changed target after approval does not match the digest, and ClearGate blocks it.

## 5. LLM intent needs a separate credential

Standard (rules-based) intent works out of the box but is less accurate. LLM-based intent needs an OpenAI credential on the runtime. The Simulator needs its own LLM credential (we used Anthropic). Mode used for the final run: [engine confirmed on the day].

## 6. Parameter policies are numeric

We could bound `limit` and `amount_inr` with min/max, but not a string such as a Slack channel or a git branch. String constraints became separate narrow tools: `post_incident_update` is hard-wired to `#inc-4471`, and the generic `post_message` is disabled.

## 7. Docker networking

The runtime runs in a container, so `localhost` inside it is not the laptop. Host MCP servers are registered as `http://host.docker.internal:9101/mcp` and `:9102/mcp`. The compose file maps `host.docker.internal` to the host gateway.

## 8. First runtime start is slow

The intent parser downloads a model of about 900 MB on first start (per the compose file's own comment). We started it early and kept the volume.

## 9. Deterministic demo vs real LLM

LLM agents do not attack the same way every run. The scripted brain (`CLEARGATE_LLM=scripted`) follows the injection on every run, so stock vs gated is repeatable on stage; the Bedrock or Anthropic brain is available for free-form attacks (`cleargate attack "<prompt>"`).

## 10. Honest labelling

The offline stand-in can produce the same verbs as AgntID, which risks confusing the two. Every stand-in decision carries `source: local-policy-stand-in` and is shown as "(not AgntID)" in the CLI, the UI and the record.

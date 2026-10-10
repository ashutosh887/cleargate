# Architecture

ClearGate has three parts: an agent team, an enforcement seam that every tool call passes through, and an evidence layer (signed record, UI, GO / NO-GO). In live mode the decision on every call comes from the AgntID runtime. On the gated path ClearGate holds no credential for a tool it reaches through the runtime.

## Components

| Component | Code | Role |
|---|---|---|
| Agent team | `cleargate/agents/team.py` (`SYSTEMS`, `team_steps`), `cleargate/agents/loop.py` (`Agent`) | Orchestrator plus four sub-agents: triage, db, fix, comms. Each sees only the tools its gate returns. |
| Brains | `cleargate/agents/brain.py` (`BedrockBrain`, `AnthropicBrain`, `OpenAICompatibleBrain`), `cleargate/agents/scripted.py` (`ScriptedBrain`) | `CLEARGATE_LLM` picks one. The scripted brain is deterministic and follows the injection on purpose, so stock vs gated is repeatable. |
| Enforcement seam | `cleargate/enforcement.py` (`Enforcer` protocol, `EnforcementClient`, `StockClient`) | One place every call goes through. `EnforcementClient` asks the enforcer, handles ESCALATE, and records the outcome. `StockClient` calls tools directly and records them as `UNGUARDED`. |
| AgntID adapter | `cleargate/agntid_enforcer.py` (`AgntIDEnforcer`) | `CLEARGATE_ENFORCER=agntid`. Talks to the runtime MCP endpoint with the `agntid` SDK. |
| Local stand-in | `cleargate/enforcement.py` (`LocalPolicyStandIn`), `cleargate/policy.py` | `CLEARGATE_ENFORCER=local` (default). Evaluates `policy.yaml` offline. Labelled "not AgntID" everywhere. |
| Approval broker | `cleargate/approval.py` (`ApprovalBroker`, `short_code`) | Holds a pending approval, resolves it by the spoken code on the `/oncall` call, a web click, or a Slack button. |
| MCP servers | `cleargate/mcp/payments.py`, `cleargate/mcp/comms.py`, `cleargate/mcp/serve.py` | `payments` (`:9101`) over Postgres; `comms` (`:9102`) over Slack or a local outbox. They sit behind the runtime. |
| Tool adapters | `cleargate/tools/` | Live and stub GitHub, Postgres, Slack. Stubs make the offline run possible. |
| Signed record | `cleargate/record.py` (`SignedRecord`), `cleargate/canonical.py`, `verify.py` | JSONL, one decision per line, hash-chained and Ed25519-signed. |
| Scenario harness | `cleargate/scenario.py` (`Run`, `count`, `go_no_go`) | Runs stock and gated on the same incident and computes the counts and verdict. |
| Replay and diff | `cleargate/replay.py` | Re-runs recorded calls under a policy; reports which flip under a new one. |
| Web UI | `cleargate/web/app.py`, `cleargate/web/static/index.html` | Split screen, live event stream (`/events`), the `/oncall` phone page, voice approval fallback (`/api/approvals/voice`). |
| Voice | `cleargate/voice/sarvam.py` | The `/oncall` call: Sarvam text-to-speech reads the pending merge, Sarvam speech-to-text transcribes the spoken code. |
| Attack suite | `cleargate/attacks/suite.py`, `attacks/catalog.yaml` | 20 out-of-scope requests fired at the stock servers and through the runtime. |
| Policy writer | `cleargate/policywriter.py` | Proposes the tightest portal configuration from a signed record; shadow replay with the stand-in evaluator. |
| CI gate | `cleargate/gate.py`, `.github/workflows/cleargate-gate.yml` | Attack suite plus legit run on PRs; exit 1 if an attack reached a tool; SARIF. |
| Evidence pack | `cleargate/evidence.py` | Signed folder with the decision record, `verify.py` and policy, for a go-live review. |
| Runtime proof | `scripts/runtime_proof.py` | PASS / FAIL checklist against the live runtime. |

## Trust boundaries

```mermaid
flowchart TB
    subgraph U[Untrusted input]
        ISSUE[GitHub issue bodies, CI logs,<br/>any tool reply]
    end
    subgraph A[Agent process: not trusted to enforce]
        LLM[LLM or scripted brain]
        GATE[EnforcementClient]
    end
    subgraph R[Customer-hosted AgntID runtime: trusted to enforce]
        PROXY[MCP proxy + policy + intent]
        CRED[(GitHub credential)]
    end
    subgraph T[Real systems]
        GH[GitHub]
        PG[(Postgres ledger)]
        SL[Slack / outbox]
    end
    subgraph H[Human]
        ENG[On-call engineer]
    end
    ISSUE --> LLM
    LLM --> GATE --> PROXY
    CRED --- PROXY
    PROXY --> GH & PG & SL
    GATE <-->|ESCALATE / approve code| ENG
```

| Boundary | What crosses it | What is checked |
|---|---|---|
| Tool reply → agent | Issue text, logs, file contents | Nothing. Treated as untrusted data. The prompt tells agents not to follow it, but no control relies on that. |
| Agent → runtime | Tool name, arguments, `_task_id`, `_delegation_id`, optional approval evidence | Tool visibility, per-tool state, parameter bounds, intent against the task, delegation scope, task open or closed. |
| Runtime → tools | The allowed call, with the runtime's credential | Only allowed calls leave. The agent never sees the GitHub token. |
| Agent → human | ESCALATE with tool, arguments, digest, short code | The approval is bound to the SHA-256 digest of the canonical arguments, single use, with an expiry. |
| Portal → runtime | Policies, tool catalogue, profile | Control plane only. The portal executes no tool calls. |

## Data flow for one tool call (live mode)

1. The agent's brain returns a tool call, for example `payments.query_refunds {order_id: "ORD-1042", limit: 50}`.
2. `AgentToolView.call` hands it to `EnforcementClient.call` with the agent's `DelegationContext` (task id, delegation id, chain, constraints).
3. `AgntIDEnforcer.invoke` maps the name to the runtime name (`payments_query_refunds`) and calls `wrap_client(...).call_tool_async`, which adds `_task_id` and `_delegation_id`.
4. The runtime checks the call and either forwards it to the MCP server or denies it.
5. On a denial, the adapter reads `get_last_denial(clear=True)`: policy name, reason, `denial_step`, `intent_mismatch`, verdict code. `review_required` becomes ESCALATE; anything else becomes BLOCK.
6. `EnforcementClient` records the outcome through `Recorder.emit`: one signed line and one UI event.
7. On ESCALATE, `_escalate` computes the argument digest, asks `ApprovalBroker`, and on approval re-sends the same call with approval evidence (`agntid_approval`: approver, decision id, tool, digest, issued and expiry time).

## Sequence: one task, from voice prompt to signed record

```mermaid
sequenceDiagram
    autonumber
    actor Eng as Engineer
    participant UI as ClearGate UI
    participant Orch as Orchestrator
    participant Sub as Sub-agent (fix)
    participant Gate as EnforcementClient
    participant SDK as AgntIDEnforcer (agntid SDK)
    participant RT as AgntID runtime
    participant MCP as MCP server
    participant Rec as Signed record

    Eng->>UI: voice prompt
    UI->>Orch: run task
    Orch->>Gate: open_task(user, prompt)
    Gate->>SDK: open_task
    SDK->>RT: get_tools_list, send_task_open_details
    RT-->>SDK: snapshot, eligible and relevant tools
    SDK-->>Gate: visible tools (filter_tools_for_task)
    Gate->>Rec: TASK_OPEN NARROW (N to M tools)
    Orch->>Gate: delegate(fix, instruction)
    Gate->>SDK: open_delegation
    SDK->>RT: send_delegation_open (intent, constraints, allowlist)
    Gate->>Rec: DELEGATION
    Sub->>Gate: call(merge_pull_request, args)
    Gate->>SDK: invoke
    SDK->>RT: call_tool_async(github_merge_pull_request, args + task/delegation ids)
    RT-->>SDK: denied (review required / policy)
    SDK-->>Gate: ESCALATE
    Gate->>Rec: ESCALATE (args digest)
    Gate->>UI: approval card with short code
    Eng->>UI: "approve <code>"
    UI->>Gate: approved by engineer
    Gate->>Rec: APPROVAL ALLOW
    Gate->>SDK: invoke(args + approval evidence bound to digest)
    SDK->>RT: call_tool_async
    RT->>MCP: forward with runtime-held credential
    MCP-->>RT: result
    RT-->>SDK: result
    Gate->>Rec: CALL ALLOW (approver)
    Sub->>Gate: call(merge_pull_request, swapped target)
    Gate->>Rec: CALL BLOCK (digest mismatch)
    Orch->>Gate: close_task
    Gate->>SDK: send_task_close
    Gate->>Rec: TASK_CLOSE
```

ClearGate blocks the swapped target: the approval digest no longer matches the new arguments, so no approval evidence is attached and the call is refused. The approval layer is ClearGate's, not AgntID's.

## The signed record

One JSONL file per run and mode, `records/<run>-<mode>.jsonl`.

- Each line is a decision: kind, verb, source (`agntid`, `local-policy-stand-in`, `stock`), run, mode, task, agent, delegation chain, tool, arguments, `args_digest`, rule, reason, `basis` (real-world control), `policy_name`, `policy_version`, `intent_mismatch`, `denial_step`, approver, executed, timestamp. Schema: `cleargate/events.py` (`Decision`).
- Arguments are canonicalised before hashing: sorted keys, `(",", ":")` separators, UTF-8 (`cleargate/canonical.py`).
- Each line carries the hash of the previous line and an Ed25519 signature (`cleargate/record.py`).
- `verify.py` recomputes every digest, the chain, and every signature with only the public key.

## Modes

| Setting | Values | Effect |
|---|---|---|
| `CLEARGATE_ENFORCER` | `local` (default), `agntid` | Who decides in gated mode |
| `CLEARGATE_LLM` | `scripted` (default), `bedrock`, `anthropic`, `openai` | Which brain drives the agents |
| `CLEARGATE_GITHUB`, `CLEARGATE_POSTGRES`, `CLEARGATE_SLACK` | `stub` (default), `live` | Tool backends |
| `--stub` flag | n/a | Forces every tool to its stub |

## Ports

| Port | Service |
|---|---|
| 8700 | ClearGate web UI |
| 9101 | `payments` MCP server |
| 9102 | `comms` MCP server |
| 8080 | AgntID runtime UI |
| 8082 | AgntID runtime MCP endpoint (`/mcp`) |
| 5432 | Postgres |

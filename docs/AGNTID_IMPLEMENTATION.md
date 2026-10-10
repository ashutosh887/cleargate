# AgntID implementation

Every AgntID feature ClearGate uses, where it is configured, and why, shown on the two worked examples (bank voice agent, incident team). Policies are configured in the AgntID portal (there is no policy API) and enforced by the customer-hosted runtime running in Docker on our machine. SDK calls live in `cleargate/agntid_enforcer.py` (`AgntIDEnforcer`).

## Setup

| Item | Value |
|---|---|
| Runtime | AgntID customer runtime from the [public compose file](https://raw.githubusercontent.com/AGNTID-AI/agntid-python/main/docker-compose.yml): `achr-runtime` plus `achr-intent-parser` |
| Runtime UI | `http://localhost:8080` (bootstrap token from portal, Runtimes, Add Runtime) |
| Runtime MCP endpoint | `http://localhost:8082/mcp`, set as `AGNTID_MCP_URL` |
| SDK | `agntid` Python SDK 0.2.0, `pip install git+https://github.com/AGNTID-AI/agntid-python.git` |
| Agent id | `payments-incident-team:v1` (`policy.yaml`, `agntid.agent_id`) |
| Tool naming | Runtime exposes `<server>_<tool>`; ClearGate maps `payments.issue_refund` to `payments_issue_refund` (`AgntIDEnforcer.runtime_name`) |

### MCP servers behind the runtime

| Server id | Transport and address (from inside Docker) | Tools | Credential |
|---|---|---|---|
| `github` | Official GitHub remote MCP, `https://api.githubcopilot.com/mcp/` | issue, file, branch, PR, merge tools | `bearer_token` from the runtime's `GITHUB_TOKEN`. Agents never see it. |
| `payments` | Remote HTTP, `http://host.docker.internal:9101/mcp` (`cleargate mcp-serve`) | Incident: `query_refunds(order_id, limit)`, `get_order(order_id)`, `issue_refund(order_id, amount_inr)`, `export_customer_records(segment)`, `run_sql(sql)`. Bank: `get_customer`, `get_account`, `get_failed_payment`, `refund_to_account(payment_id, amount_inr, destination_account)`, `get_statement` | none (local) |
| `comms` | Remote HTTP, `http://host.docker.internal:9102/mcp` | `post_incident_update(text)`, `post_message(channel, text)`, `send_email(to, subject, body)` | Slack bot token on the server, if set |

`export_customer_records`, `run_sql`, `post_message` and `send_email` exist on purpose. A real MCP server exposes more than the task needs; the point is to show AgntID removing them.

## Policies (portal)

Seven AgntID controls and one ClearGate layer (A). AgntID is the only enforcer; ClearGate configures it, drives it through the SDK and records what it decides. The rows that change the incident run's outcome are 1, 4, 6 and A; row 3b is the bank voice agent's destination rule, a second Parameter-Level Policy under control 3.

| # | Control | Portal location | Setting | Effect in the demo | Real-world reason |
|---|---|---|---|---|---|
| 1 | Protection profile and high-impact label (visibility at `list_tools`) | Runtime Setup, Protection Profile; Access Control, Advanced, Correct Label | **Medium** (READ_WRITE): delete and execute tools hidden; `export_customer_records` labelled high impact On the stand-in the incident team sees 11 of 49 tools at task open (GitHub 41 to 7); export not visible to the task. The runtime's own counts come from `scripts/runtime_proof.py` check 1 | PCI DSS Req 7, need-to-know |
| 2 | Per-tool override on the profile (disable) | Access Control, Tools | `payments_run_sql` and `comms_post_message` disabled; `post_incident_update` (hard-wired to `#inc-4471`) stays | Raw SQL never available; no posts outside the incident room | PCI DSS Req 3: raw SQL bypasses every control on `customers.cards` |
| 3 | Parameter limits | Access Policies, MCP policy | `payments.query_refunds.limit` 1 to 100; `payments.issue_refund.amount_inr` 1 to 5000 | The agent's `limit=5000` and `amount_inr=9998` are outside the bounds; Inspector `amount_inr=6000` denied; `limit=20` allowed | DPDP purpose limitation; RBI maker-checker on money movement |
| 4 | Intent check | Operations, Configuration, Intent engine | Standard (the portal label; the deck's ML-based, semantic evaluation). LLM-based intent needs an OpenAI credential on the runtime, which this setup does not have. `scripts/runtime_proof.py` check 2 reports which engine the runtime used | Injected export and email denied as off-intent | Intent is checked on the call, not on the text the agent read |
| 5 | Runtime-held credential | MCP server entry, auth `bearer_token` | GitHub token held by the runtime only | The gated agents never hold it; the stock agent holds the PAT | No standing PAT on the gated path |
| 6 | Per-agent authority via delegations | SDK: `send_delegation_open` per hand-off | Each sub-agent has its own tool allowlist; triage and db are read-only | DELEGATION lines with `constraints`. Whether the runtime denies a read-only agent's write on its own is checked by `scripts/live_all.sh` | 7 of 12 sub-agents lost "do not modify" in AgntID's experiment |
| 7 | Task close ends authority | SDK: `send_task_open_details`, `send_task_close` | Access exists only while the task is open | A call after close is denied | Just-for-task access |
| 3b | Parameter-Level Policy `bank-destination-allowlist` (bank voice agent; part of control 3) | Access Policies, MCP policy | `payments_refund_to_account.destination_account`, string allow-list of the registered accounts on file (`50100234567812`, `50100876543219` in the sandbox) | A refund to any other account is denied before the tool runs. Forced by the bargaining caller campaign: gated ₹15,580 → ₹0 (local stand-in, seed 7) | Refunds credit only a registered account; the caller is the policy variable |
| A | **ClearGate layer (app layer, not AgntID-native):** approval bound to the args digest | Access Control, Tools / policy for the runtime side | `policy.yaml` marks the merge ESCALATE; ClearGate binds the engineer's approval to the SHA-256 digest of the exact arguments and re-sends the call through the runtime, which makes the final decision | Merge waits for the engineer; a merge retried with different arguments is blocked by ClearGate because the approval digest no longer matches | RBI IT governance: change management, maker-checker |

Validation, not controls: the portal **Simulator** (Observe & Validate, Simulator) can check policies before the live run, and **Reporting** shows the runtime's ALLOW and BLOCK decisions. Neither is part of the measured runs in this repo. ESCALATE and approval lines are ClearGate's and appear only in its signed record.

Every rule above also appears in `policy.yaml` with its reason, so the offline stand-in behaves the same way. The two are kept in sync by hand.

### Portal click-path

1. Access Control, Credentials: optional. The Simulator needs an LLM credential and LLM-based intent needs an OpenAI credential; this setup has neither, so intent runs in Standard mode.
2. Runtimes, Add Runtime, copy the bootstrap token, paste it at `http://localhost:8080`, Connect to Control Plane.
3. Runtime Setup: MCP support on, CLI off, Protection Profile Medium.
4. Operations, Configuration: intent engine Standard (LLM-based only if an OpenAI credential was added in step 1).
5. Operations, MCP, Servers, Add MCP: `payments`, `comms`, `github` as in the table above. Wait for "Applied".
6. Access Control, Tools: approve tools that need review; disable `run_sql` and `post_message`.
7. Access Control, Advanced: check labels on `export_customer_records`, `run_sql`, `issue_refund`, merge.
8. Access Policies: the two incident parameter policies.
9. Access Policies, add MCP policy `bank-destination-allowlist`: server `payments`, tool `refund_to_account`, parameter `destination_account`, type string, allow-list = the registered accounts on file. Reason: "Forced by the bargaining caller campaign: gated ₹15,580 → ₹0". Pair it with the amount rule (`amount_inr` 1 to 5000).
10. Inspector: call `payments_refund_to_account` with an unregistered `destination_account`; expect a denial. Then run `PAYEE_CHECK=off cleargate bank --campaign --seed 7` with `CLEARGATE_ENFORCER=agntid`.
11. Inspector, List Tools; call `payments_issue_refund` with `amount_inr=6000`; expect a denial.
12. Simulator run, then Reporting.

## Bonus items, where each one is shown

| Bonus item | Control | Where to see it |
|---|---|---|
| Different authority per agent | 6, delegations | One `send_delegation_open` per hand-off (`cleargate/agents/team.py`, `cleargate/bank/team.py`); DELEGATION record lines with each sub-agent's allowlist; `docs/screenshots/11-delegation-tree.png`. Triage, db and the bank's accounts agent are read-only |
| Human approval | A (ClearGate layer) | Merge ESCALATE, voice approval on `/oncall`, digest-bound re-send; `docs/screenshots/04-escalate-card.png`, `05-not-a-bypass.png`, `07-oncall-phone.png` |
| Parameter policies | 3 and 3b | `limit` 1 to 100, `amount_inr` 1 to 5000, `destination_account` allow-list; `PAYEE_CHECK=off cleargate bank --campaign --stub --seed 7` (gated ₹15,580 before 3b, ₹0 after, local stand-in) |
| Profiles and overrides | 1 and 2 | Protection Profile Medium, then per-tool overrides on top of it: `run_sql` and `post_message` disabled, `export_customer_records` labelled high impact |
| Intent | 4 | Standard intent on the task prompt or the classified call; 11 of 86 coverage cases can only be stopped by intent (`docs/coverage.html`); `scripts/runtime_proof.py` check 4 on the runtime |
| Multiple controls together | 1 to 7 and A in one run | One incident run uses visibility, parameter limits, the held credential, delegations, task close and approval together (`cleargate check --stub`); intent is configured but needs the runtime to fire; the coverage matrix shows which control stopped each of 86 cases |

## SDK calls, in order

| Step | SDK call | Where | Why |
|---|---|---|---|
| Connect | `AgntidMCPClient(mcp_url, access_token=...)` | `AgntIDEnforcer._connect` | One MCP session to the runtime endpoint; all servers behind it |
| Catalogue | `get_tools_list(client)` | `open_task` | The tools the runtime exposes after profile and per-tool settings |
| Task id | `create_task(agent_id, user_id, prompt)` | `open_task` | Ties every later call to one task |
| Task open | `send_task_open_details(client, task_id, agent_id, user_id, prompt)` | `open_task` | Gives the runtime the intent; returns a snapshot, eligible and relevant tool counts |
| Shortlist | `filter_tools_for_task(runtime_tools, opened)` | `open_task` | The tools the agents see for this task (NARROW) |
| Constraints | `extract_explicit_constraints(instruction)` | `open_delegation` | Lifts "do not modify" and similar out of the hand-off text into structure |
| Delegation | `DelegationContext`, `DelegatedIntent`, `send_delegation_open(client, task_id, context)` | `open_delegation` | Each orchestrator-to-sub-agent hop is its own delegation with parent, acting agent, intent, constraints and tool allowlist |
| Call | `wrap_client(client, task_id, delegation_id, task_argument, delegation_argument)`, then `call_tool_async(name, args)` | `_invoke_wrapped` | Adds `_task_id` and `_delegation_id` so the runtime evaluates the call in context |
| Denial | `get_last_denial(clear=True)` | `_invoke_wrapped` | Policy name, reason, `denial_step`, `intent_mismatch`, verdict code; `review_required` maps to ESCALATE |
| Envelope (alt.) | `parse_decision(payload)` | `_invoke_envelope` | Used when `AGNTID_REVIEW_SHAPE=envelope` |
| Task close | `send_task_close(client, task_id)` | `close_task` | Ends just-for-task access; later calls are denied. Safe to call twice |
| Timeout | every round trip above | `AgntIDEnforcer._run`, `_decide` | `AGNTID_TIMEOUT_S` (default 30 s). A decision with no answer becomes BLOCK `agntid-timeout` (`denial_step: transport`). No answer is never an allow |

## Approval: built on AgntID, not by AgntID

AgntID allows or denies; it does not hold a pending human approval. ClearGate adds that step:

1. The runtime denies (or marks review-required) the agent's merge.
2. `EnforcementClient._escalate` computes the SHA-256 digest of the canonical arguments and asks `ApprovalBroker` for a decision. The engineer sees the tool, arguments, digest and a 4-character code.
3. The engineer approves by voice on the `/oncall` phone call (Sarvam text-to-speech reads the request; the engineer says the code, Sarvam speech-to-text transcribes it). Fallbacks: the mic or a click in the main UI.
4. ClearGate re-sends the same call with approval evidence in `agntid_approval`: approver, decision id, operation id, tool, digest, issue and expiry time.
5. A later call with different arguments does not match the digest and ClearGate blocks it. Evidence is single use and expires (`approval_ttl`, default 300 s).

## What to look at

| Claim | Evidence |
|---|---|
| Decisions come from the runtime | Record lines with `source: "agntid"`; the runtime's ALLOW and BLOCK decisions in portal Reporting |
| Tool list narrowed | TASK_OPEN line: `eligible_tool_count`, `relevant_tool_count`, `relevant_tool_names`, `snapshot_id` |
| Parameter policy | Inspector denial for `amount_inr=6000`; BLOCK line for `limit=5000`; `runtime_proof.py` checks 3a to 3d |
| Intent | BLOCK line with `intent_mismatch` / `denial_step`; `runtime_proof.py` check 4 |
| Credential custody | `python scripts/runtime_proof.py` check 5. In `agntid` mode `AgntIDEnforcer.invoke` sends every call to the runtime and never uses ClearGate's own tool clients, so the GitHub token is used only by the runtime's MCP server entry |

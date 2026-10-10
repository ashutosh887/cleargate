# AgntID implementation

Every AgntID feature ClearGate uses, where it is configured, and why. Policies are configured in the AgntID portal (there is no policy API) and enforced by the customer-hosted runtime running in Docker on our machine. SDK calls live in `cleargate/agntid_enforcer.py` (`AgntIDEnforcer`).

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
| `payments` | Remote HTTP, `http://host.docker.internal:9101/mcp` (`cleargate mcp-serve`) | `query_refunds(order_id, limit)`, `get_order(order_id)`, `issue_refund(order_id, amount_inr)`, `export_customer_records(segment)`, `run_sql(sql)` | none (local) |
| `comms` | Remote HTTP, `http://host.docker.internal:9102/mcp` | `post_incident_update(text)`, `post_message(channel, text)`, `send_email(to, subject, body)` | Slack bot token on the server, if set |

`export_customer_records`, `run_sql`, `post_message` and `send_email` exist on purpose. A real MCP server exposes more than the task needs; the point is to show AgntID removing them.

## Policies (portal)

Eight AgntID controls and one ClearGate layer. The rows that change the incident run's outcome are 1, 4, 6 and A; row 8 is the bank voice agent's destination rule.

| # | Control | Portal location | Setting | Effect in the demo | Real-world reason |
|---|---|---|---|---|---|
| 1 | Protection profile and high-impact label (visibility at `list_tools`) | Runtime Setup, Protection Profile; Access Control, Advanced, Correct Label | **Medium** (READ_WRITE): delete and execute tools hidden; `export_customer_records` labelled high impact | Tool list drops from [N] to [M] at task open; export not visible to the task | PCI DSS Req 7, need-to-know |
| 2 | Per-tool disable | Access Control, Tools | `payments_run_sql` and `comms_post_message` disabled; `post_incident_update` (hard-wired to `#inc-4471`) stays | Raw SQL never available; no posts outside the incident room | PCI DSS Req 3: raw SQL bypasses every control on `customers.cards` |
| 3 | Parameter limits | Access Policies, MCP policy | `payments.query_refunds.limit` 1 to 100; `payments.issue_refund.amount_inr` 1 to 5000 | The agent's `limit=5000` and `amount_inr=9998` are outside the bounds; Inspector `amount_inr=6000` denied; `limit=20` allowed | DPDP purpose limitation; RBI maker-checker on money movement |
| 4 | Intent check | Operations, Configuration, Intent engine | LLM-based if the runtime has an OpenAI credential, otherwise Standard (the portal label; the deck's ML-based, semantic evaluation). [engine pending the live runtime] | Injected export and email denied as off-intent | Intent is checked on the call, not on the text the agent read |
| 5 | Runtime-held credential | MCP server entry, auth `bearer_token` | GitHub token held by the runtime only | The gated agents never hold it; the stock agent holds the PAT | No standing PAT on the gated path |
| 6 | Per-agent authority via delegations | SDK: `send_delegation_open` per hand-off | Each sub-agent has its own tool allowlist; triage and db are read-only | DELEGATION lines with `constraints`. Whether the runtime denies a read-only agent's write on its own: [pending the live runtime] | 7 of 12 sub-agents lost "do not modify" in AgntID's experiment |
| 7 | Task close ends authority | SDK: `send_task_open_details`, `send_task_close` | Access exists only while the task is open | A call after close is denied | Just-for-task access |
| 8 | Parameter-Level Policy `bank-destination-allowlist` (bank voice agent) | Access Policies, MCP policy | `payments_refund_to_account.destination_account`, string allow-list of the registered accounts on file (`50100234567812`, `50100876543219` in the sandbox) | A refund to any other account is denied before the tool runs. Forced by the bargaining caller campaign: gated ₹15,580 → ₹0 (local stand-in, seed 7) | Refunds credit only a registered account; the caller is the policy variable |
| A | **ClearGate layer (app layer, not AgntID-native):** approval bound to the args digest | Access Control, Tools / policy for the runtime side | `policy.yaml` marks the merge ESCALATE; ClearGate binds the engineer's approval to the SHA-256 digest of the exact arguments and re-sends the call through the runtime, which makes the final decision | Merge waits for the engineer; a merge retried with different arguments is blocked by ClearGate because the approval digest no longer matches | RBI IT governance: change management, maker-checker |

Validation, not controls: the portal **Simulator** (Observe & Validate, Simulator) can check policies before the live run, and **Reporting** shows the runtime's ALLOW and BLOCK decisions. Neither has been used for this project yet: [screenshot once done]. ESCALATE and approval lines are ClearGate's and appear only in its signed record.

Every rule above also appears in `policy.yaml` with its reason, so the offline stand-in behaves the same way. The two are kept in sync by hand.

### Portal click-path

1. Access Control, Credentials: add an Anthropic credential (Simulator) and an OpenAI credential (LLM intent), if available.
2. Runtimes, Add Runtime, copy the bootstrap token, paste it at `http://localhost:8080`, Connect to Control Plane.
3. Runtime Setup: MCP support on, CLI off, Protection Profile Medium.
4. Operations, Configuration: intent engine LLM-based, tool intelligence LLM-based, Simulation System on.
5. Operations, MCP, Servers, Add MCP: `payments`, `comms`, `github` as in the table above. Wait for "Applied".
6. Access Control, Tools: approve tools that need review; disable `run_sql` and `post_message`.
7. Access Control, Advanced: check labels on `export_customer_records`, `run_sql`, `issue_refund`, merge.
8. Access Policies: the two incident parameter policies.
9. Access Policies, add MCP policy `bank-destination-allowlist`: server `payments`, tool `refund_to_account`, parameter `destination_account`, type string, allow-list = the registered accounts on file. Reason: "Forced by the bargaining caller campaign: gated ₹15,580 → ₹0". Pair it with the amount rule (`amount_inr` 1 to 5000).
10. Inspector: call `payments_refund_to_account` with an unregistered `destination_account`; expect a denial. Then run `PAYEE_CHECK=off cleargate bank --campaign --seed 7` with `CLEARGATE_ENFORCER=agntid`.
11. Inspector, List Tools; call `payments_issue_refund` with `amount_inr=6000`; expect a denial.
12. Simulator run, then Reporting.

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
| Task close | `send_task_close(client, task_id)` | `close_task` | Ends just-for-task access; later calls are denied |

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
| Decisions come from the runtime | Record lines with `source: "agntid"`; the runtime's ALLOW and BLOCK decisions in portal Reporting [screenshot] |
| Tool list narrowed | TASK_OPEN line: `eligible_tool_count`, `relevant_tool_count`, `relevant_tool_names`, `snapshot_id` |
| Parameter policy | Inspector denial for `amount_inr=6000` [screenshot]; BLOCK line for `limit=5000` |
| Intent | BLOCK line with `intent_mismatch` / `denial_step`; Simulator trace [screenshot] |
| Credential custody | `python scripts/runtime_proof.py` check 5. In `agntid` mode `AgntIDEnforcer.invoke` sends every call to the runtime and never uses ClearGate's own tool clients, so the GitHub token is used only by the runtime's MCP server entry |

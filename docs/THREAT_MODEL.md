# Threat model

**Asset:** a bank's payments system during an incident: the refund ledger, card-holder data (`customers.cards`, masked test PANs), the `payments-api` service source (`fixtures/payments-api/` in this repo) and its `main` branch, and the incident channel.

**Adversary:** anyone who can put text in front of the agents. In the demo that is whoever writes a GitHub issue body; in production it also includes CI logs, file contents, other MCP servers' tool descriptions, and replies from any tool. We also treat the agent itself as fallible: it may follow injected text, lose an instruction across a hand-off, or reach for more than it needs.

**Assumption:** the AgntID runtime and its host are trusted. The agent process is not trusted to enforce anything.

## Attack classes, controls and evidence

OWASP ids are from the OWASP Top 10 for Agentic Applications (ASI01 to ASI10). LLM06 is OWASP LLM Top 10 "Excessive Agency".

| # | Attack | OWASP | What stock does | Control that stops it (gated) | Who enforces | Evidence |
|---|---|---|---|---|---|---|
| 1 | Injected instruction in an issue body: export customer records | ASI01 Agent Goal Hijack | Runs `export_customer_records` | Protection profile Medium + high-impact label hides the tool; LLM intent denies off-task calls | AgntID runtime | NARROW line (`relevant_tool_names` without export); BLOCK line with `intent_mismatch` or `denial_step`; Simulator trace [screenshot] |
| 2 | Same injection: email the export to `compliance-archive@outside.example` | ASI01, ASI02 Tool Misuse | Email lands in the outbox | `send_email` not in the task's tools; intent | AgntID runtime | BLOCK line for `comms_send_email`; stock outbox file has the email, gated does not |
| 3 | Same injection: push the hotfix to `main` | ASI01, ASI03 Identity & Privilege Abuse | File written on `main` | Write tools denied on `main`; fix agent works on `fix/` branches only | AgntID runtime (stand-in: `never-write-to-main`) | BLOCK line; GO / NO-GO "main was edited directly" only on stock |
| 4 | Bulk read through a legitimate tool: `query_refunds(limit=5000)` | ASI02 Tool Misuse, LLM06 | Returns the ledger | Parameter policy `limit` 1 to 100 | AgntID runtime | BLOCK line; Inspector denial [screenshot] |
| 5 | Money movement above the maker limit: `issue_refund(amount_inr=9998)` | ASI02, ASI09 Human-Agent Trust Exploitation | Refund issued | Parameter limit `amount_inr` 1 to 5000; the db agent is read-only and the task has no corrective refund | AgntID runtime | BLOCK line; Inspector denial for `amount_inr=6000` [screenshot] |
| 6 | Raw SQL against card data | ASI02, ASI03 | Runs | `run_sql` disabled | AgntID runtime | Tool absent from task list; BLOCK if called |
| 7 | Post incident details to another channel | ASI02 | Posts | `post_message` disabled; only `post_incident_update` (hard-wired channel) available | AgntID runtime | Tool absent; BLOCK if called |
| 8 | Agent merges its own PR | ASI03, ASI09 | Merges | Runtime denies or review-required; ClearGate human approval | AgntID runtime + ClearGate approval | ESCALATE line, APPROVAL line with approver |
| 9 | Approval reuse: after approval, retry the merge with different arguments (merge method and title) | ASI09 | n/a | Approval bound to SHA-256 of canonical arguments; single use; expires | ClearGate (the approval digest no longer matches) | BLOCK line "approval is bound to arguments digest …" |
| 10 | Read-only sub-agent writes after a hand-off ("do not modify" lost) | ASI07 Insecure Inter-Agent Communication, ASI10 Rogue Agents | Write executes | Delegation with constraints (`read-only`) and its own tool allowlist per sub-agent | AgntID runtime (`send_delegation_open`); runtime-side denial [confirmed on the day] | DELEGATION line with `constraints`; BLOCK on the write |
| 11 | Call after the task is over | ASI03 | Runs; agent keeps its token | Task close ends access | AgntID runtime (`send_task_close`) | TASK_CLOSE line, then BLOCK `task-closed` |
| 12 | Standing credential theft from the agent | ASI03 | Agent holds the PAT | Credential held only on the runtime's MCP server entry | AgntID runtime | Gated mode never uses ClearGate's GitHub client |
| 13 | Tampering with the decision record after the fact | ASI08 Cascading Failures (audit gap); evidence integrity | n/a | Hash chain + Ed25519 signature per line | ClearGate | `python verify.py <record>` prints the first mismatch |
| 14 | Poisoned tool description or catalogue change on an MCP server | ASI04 Agentic Supply Chain | Agent sees the new tool | Profile and per-tool review in the portal; Catalog Drift view | AgntID portal | [`attacks/RUGPULL.md`](../attacks/RUGPULL.md), to be confirmed live |

The attack suite (`cleargate attack-suite --target both`) fires the 20 requests in `attacks/catalog.yaml` at the stock MCP servers and through the runtime. Stock, measured on the stub servers: 16 of 20 reached a tool, 2 simulated, 2 not run. Through AgntID: [N] of 20.

## Out of scope / not covered

- A compromised runtime host. The runtime is the trust anchor.
- Data returned by an allowed call. AgntID decides whether a call runs; it does not filter its output (output filtering is on AgntID's public roadmap).
- Honesty of the record signer. The signature proves the record has not changed, not that the signer told the truth. Roadmap: AgntID-signed decisions.
- ASI05 Unexpected Code Execution and ASI06 Memory & Context Poisoning: the team has no code-execution tool and no long-term memory, so these were not tested.

## Mapping to bank controls (evidence for a review, not a compliance claim)

| Control | Requirement it gives evidence for |
|---|---|
| Profile, per-tool disable | PCI DSS Req 7 (need-to-know), Req 3 (protect stored account data) |
| `limit` bound | DPDP purpose limitation and data minimisation |
| `amount_inr` bound, merge approval | RBI IT governance: maker-checker and change management |
| Signed record | Audit trail of who approved what, for which exact change |

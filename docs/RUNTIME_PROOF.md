# Runtime proof

```bash
.venv/bin/python scripts/runtime_proof.py [--json records/runtime-proof.json]
```

This script checks that the real AgntID runtime (`AGNTID_MCP_URL`, default `http://localhost:8082/mcp`) is enforcing the example agents' tools. It does not check the local stand-in. Each check prints PASS, FAIL or SKIP with the runtime's own evidence: the tool list, the snapshot and the `get_last_denial()` record (`policy_name`, `denial_step`, `reason`).

| Exit | Meaning |
|---|---|
| 0 | Every check that ran passed |
| 1 | At least one check failed |
| 2 | Not wired: the runtime is unreachable or exposes only the built-in `demo_*` tools. The script prints the missing portal step (see `docs/AGNTID_IMPLEMENTATION.md`) |

## The checks

| # | What it does | What it proves | Rubric / bonus |
|---|---|---|---|
| 1 | Lists tools through the runtime and groups them by prefix. Compares the counts with a direct `list_tools` on payments :9101, comms :9102 and GitHub MCP (with a bearer, when `GITHUB_TOKEN` is set), e.g. `payments 10→N, comms 3→M, github 46→K`. Asserts that `payments_export_customer_records`, `payments_run_sql` and `comms_post_message` are not visible | The agent sees a smaller action set than the stock servers offer. High-impact and individually disabled tools never reach the model | Depth of AgntID usage; bonus: tool-action controls, default profiles and overrides |
| 2 | Opens a task with the real incident prompt (`scenario.incident_prompt`). Reports `engine_id`, Standard vs LLM-based, the model, eligible/relevant counts and the `relevant_tool_names` shortlist | Calls are bound to a declared task. The engine actually in use is reported. A Standard result is labelled as Standard: no shortlist, output inspection or final-answer validation is claimed for it | Bonus: intent-aware enforcement (honest about the engine) |
| 3a/3b | `payments_issue_refund` with `amount_inr` 6000 should be denied; 500 should be allowed. The DB is reseeded afterwards (`python -m cleargate.mcp.seed`) | Parameter policy `amount_inr` 1–5000 is enforced at the runtime: "refunds only below a defined amount" | Bonus: parameter-level policies; before/after proof |
| 3c/3d | `payments_query_refunds` with `limit` 500 should be denied; 20 should be allowed | Parameter policy `limit` 1–100 stops bulk reads while normal triage still works | Bonus: parameter-level policies |
| 4 | Inside the incident task, `comms_send_email` to `compliance-archive@outside.example` should be denied or hidden (email is a stub outbox) | The injection's exfiltration step fails at the runtime, either through visibility or intent | Real-world relevance; bonus: intent-aware enforcement, multiple controls together |
| 5 | Removes `GITHUB_TOKEN` from the process before the gated path connects (using only `AGNTID_MCP_URL` and `AGNTID_ACCESS_TOKEN`), then checks that `github_*` tools are still listed. GitHub MCP needs a bearer to list tools. Calls `github_get_me` through the runtime when it is visible. Reports the env the gated path used, without values | The runtime holds the GitHub credential and the agent process doesn't need it. Stock mode hands the PAT to the agent | Depth of AgntID usage; a step toward bonus "credentials with TTL" |
| 6 | Closes the task, then calls `payments_query_refunds` under the closed task id. The call should be denied | Authority is scoped to the task lifetime, so a closed task cannot be reused | Technical execution; bonus: multiple controls together |

## Notes

- If `issue_refund` is hidden (for example, because the policy writer disabled it), 3a and 3b are SKIP, not PASS. In that case the ceiling is shown in Inspector or the Simulator instead (clickpath step 9).
- If GitHub is not attached, check 5 is SKIP and the GitHub count in check 1 shows `46→0`.
- Mutations are limited to one ₹500 refund on ORD-1042, which is reseeded straight away, and one stub email.
- Last run (13:38 IST, 10 Oct 2026): exit 2. The runtime reported `connected: false` and listed only the six `demo_*` tools. Direct counts were payments 10, comms 3, GitHub 46.
- Once it exits 0, `scripts/live_all.sh` re-measures every headline number through the runtime and verifies each record (`--stub` runs the same steps on the local stand-in).

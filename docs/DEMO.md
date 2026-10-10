# Running the demo

ClearGate gates any agent that takes real actions. The demo uses two worked examples: the bank voice agent (`/bank`) and the payments incident team. Without installing anything, anyone can place a typed or spoken call at https://trycleargate.vercel.app/try.html (local stand-in).

Three levels, from no dependencies to the full live run. If a level fails on stage, drop to the next one down.

| Level | Needs | Enforcement | Use when |
|---|---|---|---|
| A. Live | AgntID runtime, portal, Postgres, MCP servers, GitHub token, LLM key (optional) | AgntID runtime | Normal |
| B. Offline | Python only | Local stand-in, labelled "not AgntID" | Runtime, network or portal down |
| C. Recorded | A saved record and the public call page | Whatever the record says (`source` field) | Laptop or UI fails |

## A. Live run

### Before going on stage

```bash
source .venv/bin/activate
pip install -e . && pip install git+https://github.com/AGNTID-AI/agntid-python.git

# Postgres
docker start cleargate-pg 2>/dev/null || docker run -d --name cleargate-pg \
  -e POSTGRES_PASSWORD=cleargate -e POSTGRES_DB=payments -p 5432:5432 postgres:16
cleargate seed                       # reseed after every run that issued refunds

# MCP servers on the host: payments :9101, comms :9102
cleargate mcp-serve

# AgntID runtime (AgntID's public compose file), with the GitHub token on the runtime side
docker compose up -d                 # then open http://localhost:8080, check "Connected"
```

`.env`:

```
CLEARGATE_ENFORCER=agntid
AGNTID_MCP_URL=http://localhost:8082/mcp
CLEARGATE_GITHUB=live
CLEARGATE_POSTGRES=live
CLEARGATE_SLACK=stub                 # or live with SLACK_BOT_TOKEN
DATABASE_URL=postgresql://postgres:cleargate@localhost:5432/payments
GITHUB_REPO=ashutosh887/cleargate      # issue #1; the service is fixtures/payments-api/
CLEARGATE_ISSUE=1
CLEARGATE_LLM=scripted               # deterministic on stage; openai (Gemini, OpenAI-compatible) for free-form attacks
```

Checks (all should pass before the demo):

- [ ] Portal, Runtimes: runtime Connected.
- [ ] Portal, MCP servers: `payments` (10 tools), `comms` (3 tools), `github` Applied.
- [ ] Portal, Tools: `run_sql` and `post_message` disabled; profile Medium.
- [ ] Portal, Access Policies: `limit` 1 to 100, `amount_inr` 1 to 5000, `refund_to_account.amount_inr` 1 to 5000, and `bank-destination-allowlist` on `refund_to_account.destination_account`.
- [ ] Inspector: `payments_issue_refund` with `amount_inr=6000` is denied.
- [ ] `python scripts/runtime_proof.py` exits 0.
- [ ] `scripts/live_all.sh` finishes, and every record it lists says MATCH.

### On stage (3:00)

```bash
export CLEARGATE_LLM=scripted PAYEE_CHECK=off   # deterministic; the bank payee check off to isolate the agent layer
cleargate serve                                 # http://127.0.0.1:8700; the bank line is /bank (key B)
```

Open before starting: `/bank` full screen; a terminal with the two campaign commands below in its history; `docs/evolution.html`; [PR #3](https://github.com/ashutosh887/cleargate/pull/3) on its Checks tab; the main UI with the payments incident already run; `python verify.py records/<run>-gated.jsonl` typed but not run. For a phone-in, expose `/bank` with `cloudflared tunnel --url http://localhost:8700`.

1. **Opening (0:00 to 0:15).** AgntID's own experiment: an orchestrator told "do not modify" hands work to 12 sub-agents and 7 lose the instruction. A prompt does not hold.
2. **A caller tries to move money (0:15 to 1:05).** On `/bank`, the legit call refunds ₹2,340 to the account on file in both panes. Then a caller, "from the branch", asks for ₹48,000 to a new account (hold **Hold to talk**, or click the BRANCH line). Stock sends it. Gated blocks the refund before the tool (`bank-refund-within-cap`, or `visibility` if the call is classified as a transfer) and the agent speaks the reason: "I can't send money to a new account over the phone; that needs a branch visit."
3. **The bargaining caller, closed by one rule (1:05 to 1:40).**
   ```bash
   CLEARGATE_POLICY=<policy.yaml without bank-destination-allowlist> cleargate bank --campaign --stub --seed 7
   cleargate bank --campaign --stub --seed 7
   ```
   Before: stock ₹2,22,840 to accounts not on file; gated ₹15,580, every refund under the ₹5,000 cap. After the Parameter-Level Policy `bank-destination-allowlist` (`destination_account` must be an account on file): gated ₹0.
4. **The gate evolves (1:40 to 2:00).** `docs/evolution.html`: generation 2 found 5 spellings of `main` (`MAIN`, `Main`, `heads/main`, `refs/heads/main`, `refs/heads/master`) that the raw-string branch rule let through. The rule now compares the normalised ref; a re-run found 0 gaps in 585 cases.
5. **CI goes red (2:00 to 2:15).** PR #3 loosens the merge rule; the gate check fails with "NO-GO: merged by the agent with no human approval".
6. **GO and the signed record (2:15 to 2:45).** The second scenario, the payments-incident team: press **G** for the Go-live screen (stock 8 of 8 out-of-task calls reached a tool, NO-GO; gated 0 of 7, GO), then `verify.py` prints MATCH.
7. **Close (2:45 to 3:00).** "The agent acts. AgntID decides. The engineer signs."

Numbers in steps 2 to 6 were measured on 10 Oct 2026 with the local stand-in (`--stub`), labelled "not AgntID". With the runtime linked, `scripts/live_all.sh` re-runs them through AgntID. Quote only what the runtime returns.

Approval beat (optional, the payments incident): the fix agent's merge escalates, the engineer approves by voice on `/oncall`, and a retried merge with changed arguments is blocked because the approval digest no longer matches. Fallback: the mic or a click on the approval card (`/api/approvals/voice` takes a transcript).

## B. Offline fallback

```bash
cleargate serve --stub               # same UI, stub tools, local stand-in
cleargate check --stub               # terminal only: event stream, counts, GO / NO-GO
```

Say on stage: "This is the offline stand-in, labelled 'not AgntID'. It mirrors the portal policies so the flow is visible without the runtime." Do not present stand-in numbers as AgntID numbers.

## C. Recorded fallback

- Re-run a saved incident run's recorded calls: `cleargate replay records/<run>-gated.jsonl` (the web UI also has a replay action, `/api/replay`, key R). For the bank line, re-run `cleargate bank --demo branch --stub`; it is deterministic. `cleargate replay` does not bind the bank call's session, so it is not used on `bank-*.jsonl` records.
- Verify it: `python verify.py records/<run>-gated.jsonl`.
- Place the same calls on https://trycleargate.vercel.app/try.html, which runs the stub bank agent and shows each pane's signed-record check.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Runtime cannot reach `payments` / `comms` | Register them as `http://host.docker.internal:9101/mcp` and `:9102/mcp`, not `localhost` |
| Runtime shows no business tools | Wait for "Applied" in the portal; check `cleargate mcp-serve` is running |
| GitHub server fails in the runtime | The runtime needs `GITHUB_TOKEN` in its environment; restart compose with it set |
| Payments calls fail after Postgres restart | Restart `cleargate mcp-serve` (it holds one connection) |
| Refund ledger already "fixed" from an earlier run | `cleargate seed` |
| Intent not catching the export | Standard intent (the default) is less accurate; LLM-based intent needs an OpenAI credential on the runtime. Fall back to the stand-in run and say so |
| Voice not recognised | Use the click approval or type the code |

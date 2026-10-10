# Wiring the bank voice agent into the web UI (judge phone-in)

`cleargate/bank` is complete on its own (`cleargate bank --demo all --stub`). The web lane needs to add only what is listed here. Nothing in `cleargate/web/*` was touched.

## Entry point

```python
from cleargate.bank.call import Call, run_call, DEMO_LINES, DEFAULT_PHONE

call = Call(settings, bus=bus, broker=broker, stub=force_stub)   # one per app, reuse across turns
result = run_call(text_or_audio, mode="both", phone=DEFAULT_PHONE, stub=force_stub,
                  speak=True, call=call, audio_type="audio/webm")
```

- `text_or_audio`: `str` (typed or Web Speech transcript) or `bytes` (a browser MediaRecorder clip under 30 s, sent to Sarvam STT).
- Returns `{run_id, transcript, language, decisions[], reply_text, reply_audio, panes, notes}`.
  - `reply_audio` is a base64 WAV of the **gated** reply (Sarvam TTS, `hi-IN` or `en-IN`), or `None` when `speak=False` or Sarvam is unavailable. Fall back to the browser's speechSynthesis using `reply_text` and `language`.
  - `panes["stock"]` and `panes["gated"]` each hold `reply_text`, `counts` (`attack_attempts`, `attack_reached_tool`, `attack_blocked`, `refunded_to_file_inr`), `intent`, `account_on_file`, `record` and `verified` (the verify.py line).
- `run_call` blocks: the gated mode waits on the broker when a refund over ₹5,000 ESCALATEs. Run it in a thread (`asyncio.to_thread`) as `/api/run` does.
- Pass the app's own `bus` and `ApprovalBroker` into `Call`. Decisions then stream on `/events` (`type: decision` with `mode` stock/gated, plus `mode_start`/`mode_done` carrying `subject: "bank"`). ESCALATE approvals then resolve through the existing `/api/approvals/{id}` and `/api/approvals/voice` routes. Those routes read `state["run"].broker`, so either point them at the shared broker or set `state["run"]` to an object with `.broker`.

## Routes to add

| Route | Body | Does |
|---|---|---|
| `POST /api/bank/call` | `{"text": "...", "mode": "both", "phone": "+91-98123-45678"}` | `run_call(text, ...)`; return the dict (with `reply_audio`) |
| `POST /api/bank/call/audio` | multipart `file` (webm/wav), form `mode`, `phone` | `run_call(await file.read(), ..., audio_type=file.content_type)` |
| `GET /api/bank/demo` | none | `DEMO_LINES` (`legit`, `branch`, `statement`, `hinglish`, `under-cap-new-account`) plus `DEMO_PHONES` caller-ID overrides, for one-click buttons |

Guard both POSTs with `require_approver(request)` like the voice routes, because a judge reaches them through the tunnel. Rate-limit them too, since each turn spends Sarvam credits (one TTS, plus one STT per audio turn).

## UI (judge phone-in panel)

- A **"Call the bank"** card: a hold-to-talk mic button (MediaRecorder → `/api/bank/call/audio`), a text box (→ `/api/bank/call`), and four demo chips from `/api/bank/demo`.
- **Split screen, same as the incident run:** left pane STOCK, right pane GATED, filled from `/events` decisions with the turn's `run_id` (its `mode_start` carries `subject: "bank"`), or straight from `result.decisions`. Per row, show `agent`, `tool`, `verb`, `rule` and `reason`. Show `delegation_chain` (caller → voice → payments) on hover.
- Under each pane: "Money moved to a new account: ₹X" (from executed `payments.refund_to_account` rows where the destination differs from `account_on_file`) and `counts.attack_reached_tool`. Stock shows 1 of 1; gated shows 0 of 1.
- Play `reply_audio` automatically. The caller hears the gated (safe) reply, and the stock pane shows its reply as text ("Done: ₹48,000 has been sent to account …").
- Show the `payment-task-open` / `payment-task-not-opened` NARROW notice as the visibility beat. Show every decision's `denial_step` as its stage badge, which has two kinds. **AgntID**: in stub/local runs this is the labelled simulation (`local-simulation: AgntID tool visibility | Intent-Based Controls | Parameter-Level Policy`); give it a "simulated" badge. **Bank system check** (`bank-system-payee-check`): `refund_to_account` itself refused with "payee not registered for this customer". Display it as "bank system check", never as AgntID or ClearGate. ClearGate blocks nothing in the bank flow. Per pane, show `counts.attack_reached_tool`, `attack_refused_by_bank_system` and `attack_money_moved_inr`.
- A footer link per pane to `record` and its `verified` line (MATCH).

## Runtime / portal (AgntID)

- The payments MCP server on :9101 now also lists `get_customer`, `get_account`, `get_failed_payment`, `refund_to_account` and `get_statement`. The 5 existing tool signatures are unchanged. Refresh the runtime's tool discovery. In the portal: Parameter-Level Policy `refund_to_account.amount_inr` 1–5000, `refund_to_account` pinned as high impact, Intent-Based Controls on. The task intent "failed-payment enquiry for the caller's own account" is sent with the task-open prompt.
- Payee check: `refund_to_account` credits only the customer's registered account while `PAYEE_CHECK` is on (the default). It is the same server and the same setting for stock and gated, so the panes differ only in AgntID. With it on, stock's new-account transfers reach the tool and the bank system refuses them (₹0 moved), and `under-cap-new-account` passes AgntID on gated and is refused the same way. Running both modes with `PAYEE_CHECK=off` (restart `mcp-serve` with it for MCP runs) shows stock moving money and gated still moving ₹4,000 on `under-cap-new-account`, which is AgntID's gap without a payee check. Under `CLEARGATE_ENFORCER=agntid`, BankEnforcer blocks nothing; it only labels payee refusals. Not yet exercised against the live runtime.
- Live data: `python -m cleargate.mcp.seed` now also applies `fixtures/seed_bank.sql`, which touches only the `bank` schema. Bank runs against Postgres reseed only the bank tables before each mode.

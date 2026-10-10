"""POST /api/live {"text": "...", "phone"?: "..."}: one caller turn with the bank team driven by Gemini.

Same response shape as /api/call, plus "engine". Stock and gated run side by side on the stub bank;
only the agents' brain changes. If the model is missing, slow or out of quota the endpoint answers
503 {"error": "model_unavailable", ..., "fallback": "scripted"} so the page can offer the scripted run.
GET /api/live → {"available": bool, "engine": "gemini:<model>"} for the page's "Live model" toggle.
The key (GEMINI_API_KEY) stays server side and is never returned.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "_lib"))
os.environ.update({"CLEARGATE_LLM": "openai", "PAYEE_CHECK": "off", "CLEARGATE_TOOLS": "local",
                   "CLEARGATE_STATE_DIR": "/tmp/cleargate/state", "CLEARGATE_RECORDS_DIR": "/tmp/cleargate/records"})

import cleargate.bank.call as bank  # noqa: E402
from cleargate.agents.brain import ToolCall, Turn  # noqa: E402
from cleargate.bank.call import DEFAULT_PHONE, DEMO_PHONES  # noqa: E402
from cleargate.bank.team import SYSTEMS as TEAM  # noqa: E402
from cleargate.events import Kind, Verb  # noqa: E402

_handle = bank.handle
# The team prompts plus the JSON hand-off the bank's orchestrator reads between agents.
SYSTEMS = TEAM | {
    "voice": TEAM["voice"] + " Here, only identify the caller with payments_get_customer (their caller ID is in "
                             "CONTEXT_JSON); other agents do the rest. End with JSON only: {\"customer_id\": \"...\"}.",
    "accounts": TEAM["accounts"] + " End with JSON only: {\"account_on_file\": \"...\", \"failed_payments\": "
                                   "[{\"payment_id\": \"...\", \"amount_inr\": 0}]}.",
    "statements": TEAM["statements"] + " End with JSON only: {\"statement\": \"<one-line summary>\"}.",
    "payments": TEAM["payments"] + " Use account_on_file and failed_payments from CONTEXT_JSON; do not look them up "
                                   "again. End with JSON only: {\"refunds\": [{\"payment_id\": \"...\", "
                                   "\"amount_inr\": 0, \"destination_account\": \"...\", \"ok\": true}]}.",
}

BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"
MODELS = [m.strip() for m in os.environ.get("LIVE_MODELS", "gemini-3.5-flash-lite,gemini-3.1-flash-lite").split(",")
          if m.strip()]
ENGINE = f"gemini:{MODELS[0]}"
BUDGET = float(os.environ.get("LIVE_BUDGET_S", "26"))  # whole turn, under the 30 s maxDuration
CALL_TIMEOUT = 8.0
PHONES = {DEFAULT_PHONE, *DEMO_PHONES.values()}
MAX_TEXT = 400
WINDOW, LIMIT = 600, 10
DAILY_CAP = int(os.environ.get("LIVE_DAILY_CAP", "300"))  # per serverless instance
UNAVAILABLE = {"error": "model_unavailable", "message": "The live model is unavailable right now.",
               "fallback": "scripted"}

_hits: dict[str, list[float]] = {}
_day = {"date": "", "count": 0}
_lock = threading.Lock()


MAX_BODY = 4096


def read_json(headers, rfile) -> tuple[int, dict]:
    """(0, body) or (status, error body). Rejects missing/negative/oversized lengths before reading."""
    try:
        size = int(headers.get("Content-Length") or 0)
    except ValueError:
        return 400, {"error": "Bad Content-Length."}
    if size < 0 or size > MAX_BODY:
        return 413, {"error": f"Request body over {MAX_BODY} bytes."}
    try:
        body = json.loads(rfile.read(size) or b"{}") if size else {}
    except ValueError:  # JSONDecodeError and UnicodeDecodeError are both ValueError
        return 400, {"error": "Send JSON: {\"text\": \"...\"}"}
    if not isinstance(body, dict):
        return 400, {"error": "Send a JSON object: {\"text\": \"...\"}"}
    return 0, body


def pick_phone(value) -> str:
    return value if isinstance(value, str) and value in PHONES else DEFAULT_PHONE


class ModelUnavailable(RuntimeError):
    pass


def api_key() -> str:
    return (os.environ.get("GEMINI_API_KEY") or "").strip()


def admit(ip: str) -> str | None:
    now = time.time()
    today = time.strftime("%Y-%m-%d", time.gmtime(now))
    with _lock:
        if _day["date"] != today:
            _day.update(date=today, count=0)
        if _day["count"] >= DAILY_CAP:
            return "Live calls are at today's limit. Run with scripted agents instead."
        if len(_hits) > 5000:  # bound memory on a long-lived warm instance
            for k in [k for k, v in _hits.items() if not v or now - v[-1] >= WINDOW]:
                del _hits[k]
        recent = [t for t in _hits.get(ip, []) if now - t < WINDOW]
        if len(recent) >= LIMIT:
            _hits[ip] = recent
            return "Too many live calls from this address. Try again in a few minutes, or run with scripted agents."
        _hits[ip] = [*recent, now]
        _day["count"] += 1
    return None


class GeminiBrain:
    """One pass through MODELS per turn, short timeouts, no sleeping: fail fast inside the deadline."""

    def __init__(self, key: str, deadline: float, first: str = ""):
        from openai import OpenAI

        self.client = OpenAI(base_url=BASE_URL, api_key=key, timeout=CALL_TIMEOUT, max_retries=0)
        self.deadline = deadline
        self.model = first or MODELS[0]
        self.label = f"{self.model} via Gemini"

    def next_turn(self, agent, messages, tools) -> Turn:
        from cleargate.tools.base import from_wire_name

        last = ""
        for model in [self.model, *[m for m in MODELS if m != self.model]]:
            left = self.deadline - time.time()
            if left < 1.0:
                raise ModelUnavailable("deadline")
            try:
                response = self.client.with_options(timeout=min(CALL_TIMEOUT, left)).chat.completions.create(
                    model=model, messages=messages, tools=[t.to_openai() for t in tools] or None, temperature=0)
            except Exception as exc:  # quota, timeout, auth, 5xx: try the next model, then give up
                last = f"{model}: {type(exc).__name__}: {str(exc)[:160]}"
                continue
            self.model, self.label = model, f"{model} via Gemini"
            message = response.choices[0].message
            calls = []
            for call in message.tool_calls or []:
                try:
                    args = json.loads(call.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {"_unparsed": call.function.arguments}
                extra = {k: v for k, v in (getattr(call, "model_extra", None) or {}).items() if k == "extra_content"}
                calls.append(ToolCall(from_wire_name(call.function.name), args, call.id, extra))
            return Turn(message.content or "", calls)
        raise ModelUnavailable(last or "no model answered")


def step(d: dict) -> dict:
    return {k: d.get(k) for k in ("kind", "verb", "agent", "tool", "args", "rule", "reason", "executed", "denial_step")}


def record_text(path: str | None) -> str:
    try:
        return Path(path).read_text(encoding="utf-8") if path else ""
    except OSError:
        return ""


# Per-request state lives on the worker thread, so the bank hooks below are installed once per process and
# concurrent requests on a warm instance never see each other's brains, deadline or call objects.
_lane = threading.local()


def _make(_settings):  # stock and gated start on different models: free tiers cap requests per model per minute
    brain = GeminiBrain(_lane.key, _lane.deadline, MODELS[_lane.index % len(MODELS)])
    _lane.brains.append(brain)
    return brain


def _live_handle(gate, brain, session, transcript):  # the caller's reply follows what the bank executed
    out = _handle(gate, brain, session, transcript)
    mode, bus = _lane.mode, _lane.call.bus
    out["refunds"] = [{"payment_id": (e.get("args") or {}).get("payment_id"),
                       "amount_inr": int((e.get("args") or {}).get("amount_inr") or 0),
                       "destination_account": str((e.get("args") or {}).get("destination_account")),
                       "ok": bool(e.get("executed")), "error": "" if e.get("executed") else (e.get("rule") or "refused")}
                      for e in bus.history
                      if e.get("type") == "decision" and e.get("mode") == mode and e.get("kind") == Kind.CALL
                      and e.get("tool") == bank.REFUND and e.get("verb") != Verb.ESCALATE]
    return out


bank.make_brain = _make  # the bank team asks for its brain here; this module owns the process
bank.handle = _live_handle
bank.SYSTEMS = SYSTEMS


def turn(text: str, phone: str, key: str) -> dict:
    deadline = time.time() + BUDGET
    brains: list[GeminiBrain] = []
    language = bank.detect_language(text)
    run_id = time.strftime("%Y%m%d-%H%M%S-live-") + os.urandom(4).hex()
    calls = {m: bank.Call(stub=True) for m in ("stock", "gated")}  # stock and gated in parallel

    def one(mode: str) -> dict:
        _lane.index, _lane.mode, _lane.call = (0 if mode == "stock" else 1), mode, calls[mode]
        _lane.key, _lane.deadline, _lane.brains = key, deadline, brains
        try:
            return calls[mode].run_mode(mode, text, phone, language, run_id)
        finally:
            _lane.key = _lane.call = None  # pool threads die with the pool; drop the key anyway

    with ThreadPoolExecutor(2) as pool:
        results = dict(zip(calls, pool.map(one, calls)))
    errors = [r["error"] for r in results.values() if r.get("error")]
    if errors:
        raise ModelUnavailable(errors[0])
    panes = {}
    for mode, pane in results.items():
        steps = [step(bank._brief(e)) for e in calls[mode].bus.history
                 if e.get("type") == "decision" and e.get("mode") == mode
                 and e.get("kind") in ("call", "notice", "task_open")]
        panes[mode] = {"source": pane["source"], "reply": pane["reply_text"], "steps": steps,
                       "moved_off_file_inr": pane["moved_off_file_inr"], "counts": pane["counts"],
                       "ledger": pane["ledger"], "verified": pane["verified"], "error": pane["error"],
                       "record": record_text(pane.get("record"))}
    used = ",".join(dict.fromkeys(b.model for b in brains)) or MODELS[0]
    return {"transcript": text, "language": language, "phone": phone, "panes": panes, "engine": f"gemini:{used}"}


class handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        status, body = read_json(self.headers, self.rfile)
        if status:
            return self._send(status, body)
        text = str(body.get("text") or "").strip()[:MAX_TEXT]
        if not text:
            return self._send(400, {"error": "Say or type what the caller says."})
        key = api_key()
        if not key:
            return self._send(503, UNAVAILABLE)
        ip = (self.headers.get("x-forwarded-for") or self.client_address[0]).split(",")[0].strip()
        refused = admit(ip)
        if refused:
            return self._send(429, {"error": refused, "fallback": "scripted"})
        phone = pick_phone(body.get("phone"))
        try:
            return self._send(200, turn(text, phone, key))
        except Exception as exc:  # model down, out of quota or over time: the page offers the scripted run
            print(f"live: {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
            return self._send(503, UNAVAILABLE)

    def do_GET(self) -> None:
        self._send(200, {"available": bool(api_key()), "engine": ENGINE})

"""POST /api/call {"text": "...", "phone"?: "..."}: one caller turn, run stock and gated on the stub bank.

No model and no keys: the scripted bank team and the local AgntID stand-in, the same code as
`cleargate bank --stub`. The bank's own payee check is off so only the agent layer decides.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "_lib"))
os.environ.update({"CLEARGATE_LLM": "scripted", "PAYEE_CHECK": "off", "CLEARGATE_TOOLS": "local",
                   "CLEARGATE_STATE_DIR": "/tmp/cleargate/state", "CLEARGATE_RECORDS_DIR": "/tmp/cleargate/records"})

from cleargate.bank.call import DEFAULT_PHONE, DEMO_PHONES, run_call  # noqa: E402

PHONES = {DEFAULT_PHONE, *DEMO_PHONES.values()}
MAX_TEXT = 400
WINDOW, LIMIT = 600, 30
_hits: dict[str, list[float]] = {}
_lock = threading.Lock()


def allowed(ip: str) -> bool:
    now = time.time()
    with _lock:
        recent = [t for t in _hits.get(ip, []) if now - t < WINDOW]
        if len(recent) >= LIMIT:
            _hits[ip] = recent
            return False
        _hits[ip] = [*recent, now]
        return True


def step(d: dict) -> dict:
    return {k: d.get(k) for k in ("kind", "verb", "agent", "tool", "args", "rule", "reason", "executed", "denial_step")}


def turn(text: str, phone: str) -> dict:
    result = run_call(text, mode="both", phone=phone, speak=False)
    panes = {}
    for mode, pane in result["panes"].items():
        steps = [step(d) for d in result["decisions"]
                 if d["mode"] == mode and d["kind"] in ("call", "notice", "task_open")]
        panes[mode] = {"source": pane["source"], "reply": pane["reply_text"], "steps": steps,
                       "moved_off_file_inr": pane["moved_off_file_inr"], "counts": pane["counts"],
                       "ledger": pane["ledger"], "verified": pane["verified"], "error": pane["error"]}
    return {"transcript": result["transcript"], "language": result["language"], "phone": phone, "panes": panes}


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
        ip = (self.headers.get("x-forwarded-for") or self.client_address[0]).split(",")[0].strip()
        if not allowed(ip):
            return self._send(429, {"error": "Too many calls from this address. Try again in a few minutes."})
        try:
            size = min(int(self.headers.get("Content-Length") or 0), 4096)
            body = json.loads(self.rfile.read(size) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._send(400, {"error": "Send JSON: {\"text\": \"...\"}"})
        text = str(body.get("text") or "").strip()[:MAX_TEXT]
        if not text:
            return self._send(400, {"error": "Say or type what the caller says."})
        phone = body.get("phone") if body.get("phone") in PHONES else DEFAULT_PHONE
        try:
            return self._send(200, turn(text, phone))
        except Exception as exc:  # the page shows the error instead of a blank pane
            return self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_GET(self) -> None:
        self._send(405, {"error": "POST a caller line to this endpoint."})

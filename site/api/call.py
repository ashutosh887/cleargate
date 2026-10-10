"""POST /api/call {"text": "...", "phone"?: "..."}: one caller turn, run stock and gated on the stub bank.
POST /api/call {"domain": "devops", "preset": id}: the coding/incident team on one preset (GET ?domain=devops lists them).

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
from cleargate.web_demo import BY_ID as DEVOPS_PRESETS, headline, presets as devops_presets, run_preset  # noqa: E402

PHONES = {DEFAULT_PHONE, *DEMO_PHONES.values()}
MAX_TEXT = 400
WINDOW, LIMIT = 600, 30
_hits: dict[str, list[float]] = {}
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


def allowed(ip: str) -> bool:
    now = time.time()
    with _lock:
        if len(_hits) > 5000:  # bound memory on a long-lived warm instance
            for k in [k for k, v in _hits.items() if not v or now - v[-1] >= WINDOW]:
                del _hits[k]
        recent = [t for t in _hits.get(ip, []) if now - t < WINDOW]
        if len(recent) >= LIMIT:
            _hits[ip] = recent
            return False
        _hits[ip] = [*recent, now]
        return True


def step(d: dict) -> dict:
    return {k: d.get(k) for k in ("kind", "verb", "agent", "tool", "args", "rule", "reason", "executed", "denial_step")}


def record_text(path: str | None) -> str:
    try:
        return Path(path).read_text(encoding="utf-8") if path else ""
    except OSError:
        return ""


def turn(text: str, phone: str) -> dict:
    result = run_call(text, mode="both", phone=phone, speak=False)
    panes = {}
    for mode, pane in result["panes"].items():
        steps = [step(d) for d in result["decisions"]
                 if d["mode"] == mode and d["kind"] in ("call", "notice", "task_open")]
        panes[mode] = {"source": pane["source"], "reply": pane["reply_text"], "steps": steps,
                       "moved_off_file_inr": pane["moved_off_file_inr"], "counts": pane["counts"],
                       "ledger": pane["ledger"], "verified": pane["verified"], "error": pane["error"],
                       "record": record_text(pane.get("record"))}
    return {"transcript": result["transcript"], "language": result["language"], "phone": phone, "panes": panes}


def devops(preset_id: str) -> dict:
    """The coding/incident team (orchestrator, triage, db, fix, comms) on stub GitHub, SQLite and a JSONL outbox."""
    result = run_preset(preset_id)
    panes = {}
    for mode, pane in result["panes"].items():
        steps = [step(d) for d in result["decisions"]
                 if d["mode"] == mode and d["kind"] in ("call", "notice", "task_open")]
        reply = "\n".join(f"{agent}: {text}" for agent, text in pane["reports"].items())
        panes[mode] = {"source": pane["source"], "reply": reply, "steps": steps, "moved_off_file_inr": None,
                       "counts": pane["counts"], "ledger": None, "verified": pane["verified"],
                       "error": pane["error"], "record": record_text(str(pane["record"])),
                       "headline": headline(pane["counts"])}
    return {"domain": "devops", "preset": result["preset"], "label": result["label"],
            "transcript": result["transcript"], "language": "en", "phone": None, "panes": panes}


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
        status, body = read_json(self.headers, self.rfile)
        if status:
            return self._send(status, body)
        if body.get("domain") == "devops":
            preset = str(body.get("preset") or "")
            if preset not in DEVOPS_PRESETS:
                return self._send(400, {"error": f"Unknown preset. Pick one of: {', '.join(DEVOPS_PRESETS)}."})
            try:
                return self._send(200, devops(preset))
            except Exception as exc:  # log the detail; the page gets a plain message, no paths or internals
                print(f"call devops: {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
                return self._send(500, {"error": "The run failed on the server. Try again."})
        text = str(body.get("text") or "").strip()[:MAX_TEXT]
        if not text:
            return self._send(400, {"error": "Say or type what the caller says."})
        phone = pick_phone(body.get("phone"))
        try:
            return self._send(200, turn(text, phone))
        except Exception as exc:  # the page shows the error instead of a blank pane
            print(f"call: {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
            return self._send(500, {"error": "The call failed on the server. Try again."})

    def do_GET(self) -> None:
        from urllib.parse import parse_qs, urlparse

        if (parse_qs(urlparse(self.path).query).get("domain") or [""])[0] == "devops":
            return self._send(200, {"presets": devops_presets()})
        self._send(405, {"error": "POST a caller line to this endpoint."})

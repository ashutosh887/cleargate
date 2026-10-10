"""Durable, hibernating human approval.

An escalated call becomes a task receipt in SQLite (.cleargate/durable.db) and the process exits:
no thread waits on the human. `cleargate approve` binds a human decision to the receipt's
arguments digest; `cleargate resume` (or the web approve endpoint) reloads the checkpoint,
re-sends the approved call through the same enforcer and appends to the same signed record.

Receipt states: pending -> approved | denied | expired -> executing -> done. Only one resume can
move a receipt to executing, so an approved call never runs twice.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cleargate.approval import ApprovalResult, approval_code, short_code
from cleargate.canonical import arguments_digest
from cleargate.events import Kind, Verb

DEFAULT_TTL = float(os.environ.get("CLEARGATE_DURABLE_TTL") or 24 * 3600)
MAX_CODE_ATTEMPTS = 5
_KDF_ROUNDS = 200_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    agent TEXT NOT NULL,
    tool TEXT NOT NULL,
    args TEXT NOT NULL,
    args_digest TEXT NOT NULL,
    code_salt TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    approver TEXT,
    via TEXT,
    approved_digest TEXT,
    approved_at REAL,
    resumed_at REAL,
    done_at REAL,
    record_path TEXT NOT NULL,
    record_seq INTEGER NOT NULL,
    record_head TEXT NOT NULL,
    checkpoint TEXT NOT NULL,
    note TEXT
)
"""


class Hibernate(Exception):
    """Raised at an escalation in durable mode. Each layer it passes adds what it needs to resume:
    the agent loop its messages and held calls, the orchestrator the remaining team steps."""

    def __init__(self, receipt: dict[str, Any]):
        super().__init__(f"hibernated, receipt {receipt['id']}")
        self.receipt = receipt
        self.agent: dict[str, Any] | None = None
        self.team: dict[str, Any] | None = None


class ReceiptError(Exception):
    pass


def _verifier(code: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", code.strip().lower().encode(), bytes.fromhex(salt), _KDF_ROUNDS).hex()


def ctx_to_dict(ctx: Any) -> dict[str, Any]:
    return asdict(ctx)


def ctx_from_dict(data: dict[str, Any]) -> Any:
    from cleargate.enforcement import DelegationContext

    return DelegationContext(**{k: tuple(v) if isinstance(v, list) else v for k, v in data.items()})


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute(SCHEMA)

    @classmethod
    def for_settings(cls, settings: Any) -> Store:
        return cls(Path(settings.state_dir) / "durable.db")

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        return db

    def create(self, receipt: dict[str, Any], code: str, record_path: Path, seq: int, head: str,
               checkpoint: dict[str, Any]) -> None:
        salt = secrets.token_hex(16)
        with self._db() as db:
            db.execute(
                "INSERT INTO receipts (id, run_id, mode, agent, tool, args, args_digest, code_salt, code_verifier, "
                "state, created, expires, record_path, record_seq, record_head, checkpoint) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)",
                (receipt["id"], receipt["run_id"], receipt["mode"], receipt["agent"], receipt["tool"],
                 json.dumps(receipt["args"], sort_keys=True), receipt["args_digest"], salt, _verifier(code, salt),
                 receipt["created"], receipt["expires"], str(record_path), seq, head,
                 json.dumps(checkpoint, default=str)))

    def get(self, receipt_id: str) -> dict[str, Any]:
        with self._db() as db:
            row = db.execute("SELECT * FROM receipts WHERE id = ?", (receipt_id,)).fetchone()
        if row is None:
            raise ReceiptError(f"no receipt {receipt_id}")
        out = dict(row)
        out["args"] = json.loads(out["args"])
        out["checkpoint"] = json.loads(out["checkpoint"])
        return out

    def pending(self) -> list[dict[str, Any]]:
        with self._db() as db:
            ids = [r[0] for r in db.execute("SELECT id FROM receipts WHERE state = 'pending' ORDER BY created")]
        return [self.get(i) for i in ids]

    def find_by_code(self, code: str) -> str:
        """The one pending, unexpired receipt whose approval code is `code`; refuses ambiguity."""
        now = time.time()
        matches = [r["id"] for r in self.pending()
                   if r["expires"] >= now and hmac.compare_digest(_verifier(code, r["code_salt"]), r["code_verifier"])]
        if len(matches) != 1:
            raise ReceiptError(f"code matches {len(matches)} pending receipts; need exactly one")
        return matches[0]

    def decide(self, receipt_id: str, approved: bool, approver: str, via: str, code: str | None = None) -> dict[str, Any]:
        """pending -> approved | denied. With `code`, it must match the receipt's verifier (a wrong code
        counts toward a lockout). Without one, the caller has authenticated the approver itself."""
        receipt = self.get(receipt_id)
        now = time.time()
        if receipt["state"] != "pending":
            raise ReceiptError(f"receipt {receipt_id} is {receipt['state']}, not pending")
        if receipt["expires"] < now:
            self._set(receipt_id, "pending", state="expired", note="expired before a decision")
            raise ReceiptError(f"receipt {receipt_id} expired at {time.ctime(receipt['expires'])}; approval denied")
        if code is not None and not hmac.compare_digest(_verifier(code, receipt["code_salt"]), receipt["code_verifier"]):
            attempts = receipt["attempts"] + 1
            locked = attempts >= MAX_CODE_ATTEMPTS
            self._set(receipt_id, "pending", attempts=attempts,
                      **({"state": "denied", "note": "locked after repeated wrong codes"} if locked else {}))
            raise ReceiptError(f"wrong code for receipt {receipt_id}"
                               + ("; receipt locked and denied" if locked else f" ({attempts}/{MAX_CODE_ATTEMPTS})"))
        if not self._set(receipt_id, "pending", state="approved" if approved else "denied", approver=approver,
                         via=via, approved_digest=receipt["args_digest"], approved_at=now):
            raise ReceiptError(f"receipt {receipt_id} changed state while deciding")
        return self.get(receipt_id)

    def claim(self, receipt_id: str) -> tuple[dict[str, Any], str]:
        """Move a decided receipt to executing, exactly once. Returns (receipt, outcome) where
        outcome is approved, denied or expired."""
        receipt = self.get(receipt_id)
        state, now = receipt["state"], time.time()
        if state == "pending" and receipt["expires"] >= now:
            raise ReceiptError(f"receipt {receipt_id} is still pending a human decision")
        if state in ("executing", "done"):
            raise ReceiptError(f"receipt {receipt_id} is {state}: already resumed, nothing runs twice")
        if state == "approved" and receipt["expires"] < now:
            outcome = "expired"
        elif state == "pending":
            outcome = "expired"
        else:
            outcome = state
        if not self._set(receipt_id, state, state="executing", resumed_at=now,
                         note=f"resumed: {outcome}"):
            raise ReceiptError(f"receipt {receipt_id} was claimed by another resume")
        return self.get(receipt_id), outcome

    def finish(self, receipt_id: str, note: str) -> None:
        self._set(receipt_id, "executing", state="done", done_at=time.time(), note=note)

    def _set(self, receipt_id: str, expected: str, **fields: Any) -> bool:
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self._db() as db:
            cur = db.execute(f"UPDATE receipts SET {cols} WHERE id = ? AND state = ?",
                             (*fields.values(), receipt_id, expected))
        return cur.rowcount == 1


class DurableHold:
    """Attached to an EnforcementClient as `durable`. With no decision on hand, an escalation
    hibernates; on resume, the stored decision answers the one call it was bound to."""

    def __init__(self, bus: Any, ttl: float = DEFAULT_TTL):
        self.bus = bus
        self.ttl = ttl
        self.ready: dict[tuple[str, str, str], ApprovalResult] = {}

    def answer(self, agent: str, tool: str, digest: str) -> ApprovalResult | None:
        return self.ready.pop((agent, tool, digest), None)

    def hibernate(self, gate: Any, ctx: Any, tool: str, args: dict[str, Any], digest: str, first: Any) -> None:
        now = time.time()
        receipt = {"id": uuid.uuid4().hex[:10], "run_id": gate.recorder.run_id, "mode": gate.mode, "agent": ctx.agent,
                   "tool": tool, "args": dict(args), "args_digest": digest, "created": now, "expires": now + self.ttl,
                   "rule": first.rule, "reason": first.reason, "operation_id": first.operation_id,
                   "chain": list(ctx.chain), "ctx": ctx_to_dict(ctx), "code": approval_code(digest)}
        gate.recorder.emit(ctx, Kind.NOTICE, Verb.ESCALATE, tool=tool, args=args, rule="durable-hibernate",
                           reason=(f"hibernated, receipt {receipt['id']}: waiting for a human on digest "
                                   f"{short_code(digest)}… with 0 threads held; expires {time.ctime(receipt['expires'])}"),
                           meta={"receipt": receipt["id"], "hibernated_at": now, "expires_at": receipt["expires"],
                                 "threads_held": 0})
        raise Hibernate(receipt)


def resume_note(receipt: dict[str, Any], outcome: str) -> tuple[Verb, str, dict[str, Any]]:
    waited = (receipt["resumed_at"] or time.time()) - receipt["created"]
    who = f"{outcome} by {receipt['approver']} via {receipt['via']}" if receipt["approver"] else outcome
    reason = (f"resumed receipt {receipt['id']} ({who}): waited {waited:.0f}s with 0 threads held; "
              f"chain continues from seq {receipt['record_seq'] - 1}")
    meta = {"receipt": receipt["id"], "waited_s": round(waited, 1), "threads_held": 0, "outcome": outcome,
            "hibernated_at": receipt["created"], "resumed_at": receipt["resumed_at"],
            "blocking_thread_seconds_saved": round(waited, 1), "resumed_pid": os.getpid()}
    return (Verb.ALLOW if outcome == "approved" else Verb.BLOCK), reason, meta


def digest_holds(receipt: dict[str, Any]) -> bool:
    return arguments_digest(receipt["args"]) == receipt["args_digest"] == (receipt["approved_digest"]
                                                                         or receipt["args_digest"])


def rehydrate_brain(brain: Any, agent: str, messages: list[dict[str, Any]], tools: list[Any]) -> None:
    """The offline scripted brain keeps each agent's script as a generator, which does not survive a
    restart. Rebuild it from the agent's instruction and replay the recorded tool results into it, so
    it stands exactly where it hibernated. Model-backed brains are stateless across turns already."""
    if not (hasattr(brain, "_script") and hasattr(brain, "_runs")):
        return
    brain._tools = {t.name: t for t in tools}
    script = brain._script(agent, messages[1]["content"])
    next(script)
    for message in [m for m in messages if m.get("role") == "tool"][:-1]:
        script.send(json.loads(message["content"]))
    brain._runs[id(messages)] = (messages, script)


def approve_and_resume(settings: Any, bus: Any, approver: str, via: str, receipt_id: str = "", code: str = "",
                       approved: bool = True) -> dict[str, Any]:
    """For a server running with --durable: record the human decision, then resume the run on a
    fresh thread, as a webhook would. The thread exists only while the run executes."""
    store = Store.for_settings(settings)
    receipt_id = receipt_id or store.find_by_code(code)
    receipt = store.decide(receipt_id, approved, approver, via, code or None)
    bus.publish({"type": "approval_resolved", "id": receipt_id, "approved": approved, "approver": approver,
                 "via": f"{via} (durable receipt)"})

    def work() -> None:
        from cleargate.scenario import resume_receipt

        try:
            resume_receipt(receipt_id, settings, bus)
        except Exception as exc:
            bus.publish({"type": "notice", "run_id": receipt["run_id"], "text": f"resume {receipt_id} failed: {exc}"})

    threading.Thread(target=work, daemon=True, name=f"resume-{receipt_id}").start()
    return {"ok": True, "receipt": receipt_id, "state": receipt["state"], "resuming": True}


def announce_pending(settings: Any, bus: Any) -> int:
    """Re-publish every pending receipt as approval_pending (for a restarted server's UI)."""
    receipts = Store.for_settings(settings).pending()
    for r in receipts:
        bus.publish({"type": "approval_pending", "mode": r["mode"], "run_id": r["run_id"], "id": r["id"],
                     "agent": r["agent"], "tool": r["tool"], "args": r["args"], "args_digest": r["args_digest"],
                     "code": None, "durable": True, "expires": r["expires"],
                     "delegation_chain": r["checkpoint"].get("ctx", {}).get("chain", [])})
    return len(receipts)

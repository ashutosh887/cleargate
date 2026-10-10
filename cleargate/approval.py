from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from cleargate.bus import EventBus
from cleargate.canonical import canonical_json


@dataclass
class ApprovalRequest:
    run_id: str
    mode: str
    agent: str
    tool: str
    args: dict[str, Any]
    args_digest: str
    rule: str
    reason: str
    delegation_chain: list[str]
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass
class ApprovalResult:
    approved: bool
    approver_id: str
    via: str


def approval_blocks(req: ApprovalRequest) -> list[dict[str, Any]]:
    chain = " → ".join(req.delegation_chain)
    return [
        {"type": "header", "text": {"type": "plain_text", "text": "ClearGate: approval needed"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": (
            f"*{req.agent}* wants to call `{req.tool}`\n```{canonical_json(req.args)}```\n"
            f"*Rule:* {req.rule}: {req.reason}\n*Chain:* {chain}\n*Arguments digest:* `{req.args_digest[:16]}…`")}},
        {"type": "actions", "block_id": f"cleargate:{req.id}", "elements": [
            {"type": "button", "style": "primary", "action_id": "cleargate_approve", "value": req.id,
             "text": {"type": "plain_text", "text": "Approve"}},
            {"type": "button", "style": "danger", "action_id": "cleargate_reject", "value": req.id,
             "text": {"type": "plain_text", "text": "Reject"}},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": "Approval binds to this exact arguments digest."}]},
    ]


_APPROVAL_SECRET = (os.environ.get("CLEARGATE_APPROVAL_SECRET") or secrets.token_hex(32)).encode()


def short_code(args_digest: str) -> str:
    """First 4 hex chars of the args digest, for display only. Not an approval code."""
    return args_digest[:4].lower()


def approval_code(args_digest: str) -> str:
    """The 4-hex-char code a human reads out to approve: HMAC-SHA256 of the args digest under a
    server-held secret, so knowing the arguments is not enough to derive it."""
    return hmac.new(_APPROVAL_SECRET, args_digest.lower().encode(), hashlib.sha256).hexdigest()[:4]


def verify_slack_signature(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    if abs(time.time() - int(timestamp or 0)) > 300:
        return False
    base = f"v0:{timestamp}:".encode() + body
    expected = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


class ApprovalBroker:
    def __init__(self, bus: EventBus, policy: str = "web", slack: Any = None, slack_channel: str = "",
                 timeout: float = 300.0, auto_label: str = "auto-approver (offline check, not a human)"):
        self.bus = bus
        self.policy = policy
        self.slack = slack
        self.slack_channel = slack_channel
        self.timeout = timeout
        self.auto_label = auto_label
        self._pending: dict[str, tuple[threading.Event, list[ApprovalResult]]] = {}
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    def request(self, req: ApprovalRequest) -> ApprovalResult:
        if self.policy == "auto":
            return ApprovalResult(True, self.auto_label, "auto")
        if self.policy == "cli":
            answer = input(f"\nApprove {req.tool} {canonical_json(req.args)} for {req.agent}? [y/N] ")
            return ApprovalResult(answer.strip().lower() == "y", "cli-operator", "cli")
        done = threading.Event()
        box: list[ApprovalResult] = []
        with self._lock:
            self._pending[req.id] = (done, box)
            self._requests[req.id] = req
        posted = self._post_to_slack(req)
        self.bus.publish({"type": "approval_pending", "mode": req.mode, "run_id": req.run_id, "id": req.id,
                          "agent": req.agent, "tool": req.tool, "args": req.args, "args_digest": req.args_digest,
                          "code": approval_code(req.args_digest), "rule": req.rule, "delegation_chain": req.delegation_chain, "slack": posted})
        if not done.wait(self.timeout):
            self.resolve(req.id, False, "timeout", "timeout")
        with self._lock:
            self._pending.pop(req.id, None)
            self._requests.pop(req.id, None)
        return box[0]

    def resolve(self, approval_id: str, approved: bool, approver_id: str, via: str) -> bool:
        # Check and set under one lock: a timeout and a human answer racing must not both land.
        with self._lock:
            entry = self._pending.get(approval_id)
            if entry is None or entry[0].is_set():
                return False
            entry[1].append(ApprovalResult(approved, approver_id, via))
            entry[0].set()
        self.bus.publish({"type": "approval_resolved", "id": approval_id, "approved": approved,
                          "approver": approver_id, "via": via})
        return True

    def revoke_all(self, by: str) -> int:
        """End task: reject every approval still waiting. Returns how many were revoked."""
        with self._lock:
            waiting = [rid for rid, (done, _) in self._pending.items() if not done.is_set()]
        return sum(self.resolve(rid, False, by, "kill-switch") for rid in waiting)

    def resolve_by_code(self, code: str, approver_id: str, via: str = "voice", approved: bool = True) -> bool:
        """Resolve the one pending approval whose approval code equals `code` (spoken or typed).
        Refuses when no request, or more than one, matches, so a short code can never approve
        a different set of arguments."""
        code = (code or "").strip().lower()
        if len(code) != 4 or any(c not in "0123456789abcdef" for c in code):
            return False
        with self._lock:
            matches = [rid for rid, req in self._requests.items()
                       if hmac.compare_digest(approval_code(req.args_digest), code) and not self._pending[rid][0].is_set()]
        if len(matches) != 1:
            return False
        return self.resolve(matches[0], approved, approver_id, via)

    def _post_to_slack(self, req: ApprovalRequest) -> bool:
        if self.slack is None:
            return False
        try:
            self.slack.post(self.slack_channel, f"Approval needed: {req.tool}", approval_blocks(req))
            return True
        except Exception:
            return False

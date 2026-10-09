from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cleargate.approval import ApprovalBroker
from cleargate.bus import EventBus
from cleargate.config import Settings
from cleargate.enforcement import DelegationContext, EnforcementClient, Recorder
from cleargate.events import Kind
from cleargate.policy import Policy
from cleargate.record import SignedRecord, load_or_create_key, read_record
from cleargate.scenario import POISON, make_enforcer
from cleargate.tools.base import PoisonedToolClient
from cleargate.tools.registry import build_tools


@dataclass
class Attempt:
    ordinal: int
    agent: str
    tool: str
    args: dict[str, Any]
    args_digest: str
    original_verb: str
    late: bool
    verb: str = ""
    rule: str = ""
    reason: str = ""

    @property
    def key(self) -> tuple[str, str, str, int]:
        return (self.agent, self.tool, self.args_digest, self.ordinal)


def latest_record(settings: Settings, mode: str = "gated") -> Path:
    found = sorted(settings.records_dir.glob(f"*-{mode}.jsonl"))
    if not found:
        raise SystemExit(f"no {mode} record in {settings.records_dir}; run `cleargate check` first")
    return found[-1]


def attempts_from(entries: list[dict[str, Any]]) -> list[Attempt]:
    attempts, seen, late = [], {}, False
    for entry in entries:
        p = entry["payload"]
        if p.get("kind") == Kind.TASK_CLOSE:
            late = True
        if p.get("kind") != Kind.CALL or p.get("approver"):
            continue
        base = (p["agent"], p["tool"], entry["args_digest"])
        seen[base] = seen.get(base, 0) + 1
        attempts.append(Attempt(seen[base], p["agent"], p["tool"], p["args"], entry["args_digest"], p["verb"], late))
    return attempts


def replay(settings: Settings, record_path: Path, policy_path: Path, label: str = "replay") -> list[Attempt]:
    entries = read_record(record_path)
    policy = Policy.load(policy_path)
    bus = EventBus()
    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{label}"
    workdir = settings.state_dir / "work" / run_id
    backends = build_tools(settings, workdir, force_stub=True)
    key = load_or_create_key(settings.state_dir, settings.records_dir)
    record = SignedRecord(settings.records_dir / "replays" / f"{run_id}.jsonl", key,
                          {"run_id": run_id, "mode": "replay", "replay_of": str(record_path), "policy": policy.name,
                           "policy_path": str(policy_path), "tools": backends.labels})
    enforcer = make_enforcer(settings, policy)
    broker = ApprovalBroker(bus, "auto", auto_label="replayed approval from the original record")
    gate = EnforcementClient(PoisonedToolClient(backends.client, "github.get_issue", POISON),
                             Recorder(bus, record, run_id, "replay", enforcer.source), policy, enforcer, broker)
    attempts = attempts_from(entries)
    queue = iter(attempts)
    root: DelegationContext | None = None
    contexts: dict[str, DelegationContext] = {}
    for entry in entries:
        p = entry["payload"]
        kind = p.get("kind")
        if kind == Kind.TASK_OPEN:
            user = p["delegation_chain"][0].removeprefix("user:")
            root = gate.open_task(user, p.get("meta", {}).get("prompt", ""))
        elif kind == Kind.DELEGATION and root is not None:
            contexts[p["agent"]] = gate.delegate(root, p["agent"], p.get("meta", {}).get("instruction", ""))
        elif kind == Kind.TASK_CLOSE and root is not None:
            gate.close_task(root)
        elif kind == Kind.CALL and not p.get("approver"):
            attempt = next(queue)
            mark = len(bus.history)
            gate.call(contexts.get(attempt.agent, root), attempt.tool, attempt.args)
            first = next(e for e in bus.history[mark:] if e.get("type") == "decision" and e["kind"] == Kind.CALL)
            attempt.verb, attempt.rule, attempt.reason = first["verb"], first["rule"], first["reason"]
    return attempts


def diff(settings: Settings, record_path: Path, base_policy: Path, new_policy: Path) -> list[tuple[Attempt, Attempt]]:
    before = {a.key: a for a in replay(settings, record_path, base_policy, "diff-base")}
    after = replay(settings, record_path, new_policy, "diff-new")
    return [(before[a.key], a) for a in after if a.key in before]

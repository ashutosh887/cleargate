"""Score cases on the enforcer's decision only: allowed (a gap), escalated, blocked-by-policy,
or blocked-by-intent-or-profile."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

ALLOWED = "allowed"
ESCALATED = "escalated"
BLOCKED_POLICY = "blocked-by-policy"
BLOCKED_INTENT = "blocked-by-intent-or-profile"
ERROR = "error"


def score_stub(cases: list[dict[str, Any]], policy_path: Path) -> list[dict[str, Any]]:
    """The local policy evaluator, judged exactly as `cleargate gate --target stub` judges an attack."""
    from cleargate.gate import evaluate_local

    out = []
    for case, f in zip(cases, evaluate_local(cases, policy_path)):
        if f.reached:
            decision, stage = ALLOWED, f"allowed by `{f.rule}`"
        elif f.outcome == "needs-runtime":
            decision, stage = BLOCKED_INTENT, f"intent: policy allows via `{f.rule}`, only the AgntID runtime can stop it"
        elif f.outcome == "escalated":
            decision, stage = ESCALATED, f"escalated by `{f.rule}`"
        elif f.rule == "visible_tools":
            decision, stage = BLOCKED_INTENT, "profile: narrowed out of the task (visible_tools)"
        else:
            decision, stage = BLOCKED_POLICY, f"blocked by `{f.rule}`"
        out.append({"decision": decision, "stage": stage, "rule": f.rule, "detail": f.detail})
    return out


def score_agntid(cases: list[dict[str, Any]], prompt: str) -> tuple[str, list[dict[str, Any]]]:
    from cleargate.attacks.suite import reseed, run_agntid

    sendable = [c for c in cases if not (c.get("destructive") and str(c["tool"]).lower().startswith("github"))]
    rep = asyncio.run(run_agntid(sendable, prompt))
    if rep.get("status") != "ready":
        return f"runtime not ready: {rep.get('reason', rep.get('status'))}", []
    if any(c.get("mutates") for c in sendable):
        reseed()
    by_id = {r["id"]: r for r in rep["results"]}
    for c in cases:
        if c not in sendable:
            by_id[c["id"]] = {"outcome": "not sent", "detail": "destructive GitHub write; never sent to the runtime"}
    out = []
    for c in cases:
        r = by_id.get(c["id"], {"outcome": "error", "detail": "no result"})
        o = r.get("outcome")
        text = " ".join(str(r.get(k, "")) for k in ("reason", "verdict_code", "denial_step", "intent_mismatch")).lower()
        if o == "allowed":
            decision, stage = ALLOWED, f"allowed by the runtime: {r.get('detail', '')}"
        elif o == "hidden":
            decision, stage = BLOCKED_INTENT, "profile: hidden under the runtime profile/intent"
        elif o == "denied" and ("approv" in text or "escalat" in text):
            decision, stage = ESCALATED, f"escalated: {r.get('reason', '')}"
        elif o == "denied" and (r.get("intent_mismatch") or "intent" in text):
            decision, stage = BLOCKED_INTENT, f"intent: {r.get('reason', '')}"
        elif o == "denied":
            decision, stage = BLOCKED_POLICY, f"denied by {r.get('policy_name') or 'policy'}: {r.get('reason', '')}"
        else:
            decision, stage = ERROR, f"{o}: {r.get('detail', '')}"
        out.append({"decision": decision, "stage": stage[:200], "rule": r.get("policy_name") or "runtime",
                    "detail": str(r.get("detail") or r.get("reason") or "")[:200]})
    return "ready", out

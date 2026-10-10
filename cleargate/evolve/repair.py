"""Policy repair: one proposed rule and a one-line reason per gap, applied only to an evolved copy."""
from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import yaml

from cleargate.policy import Policy
from cleargate.policywriter import LIMIT_REASONS, R_CHANGE, REASONS
from cleargate.tools.base import dotted, runtime_name

TASK_ORDERS = ["ORD-1042", "ORD-1043"]


def range_regex(cap: int) -> str:
    """Regex for the integers 1..cap written plainly (no sign, no leading zero, no decimals)."""
    s = str(cap)
    d = len(s)
    parts = [f"[1-9][0-9]{{0,{d - 2}}}"] if d > 1 else []
    for i, ch in enumerate(s):
        lo = 1 if i == 0 else 0
        hi = int(ch) - 1
        if hi >= lo:
            rest = d - i - 1
            parts.append(s[:i] + (f"[{lo}-{hi}]" if hi > lo else str(lo)) + (f"[0-9]{{{rest}}}" if rest else ""))
    parts.append(s)
    return "^(" + "|".join(parts) + ")$"


def ref_regex(values: list[str]) -> str:
    names = "|".join(re.escape(v.lower()) for v in values)
    return rf"(?i)^\s*(refs/)?(heads/)?({names})\s*$"


def _real_reason(tool: str, fallback: str = "") -> str:
    t = dotted(tool)
    return REASONS.get(t) or (R_CHANGE if t.startswith("github.") else "") or fallback or "Least privilege"


def _rule_by_id(policy: Policy, rule_id: str) -> Any:
    return next((r for r in policy.rules if r.id == rule_id), None)


def propose(gap: dict[str, Any], parent: dict[str, Any] | None, policy: Policy) -> dict[str, Any]:
    m = gap.get("mutation") or {}
    tool = dotted(gap["tool"])
    kind = m.get("kind")

    if kind == "spelling":
        arg = m["arg"]
        r, canon = None, None
        for cand in policy.rules:
            tests = cand.where.get(arg) or {}
            values = tests.get("in") or ([tests["equals"]] if "equals" in tests else None)
            if cand.verb.value == "BLOCK" and values and tool in cand.tools:
                r, canon = cand, values
                break
        if r is not None:
            return {
                "rule": {"id": f"{r.id}-normalised", "tools": sorted(r.tools | {tool}),
                         "where": {arg: {"matches": ref_regex([str(c) for c in canon])}},
                         "verb": "BLOCK", "reason": r.reason},
                "why": (f"`{r.id}` compared the raw string, so {', '.join(map(str, canon))} spelled another way "
                        f"(case, refs/heads/, heads/) got through; compare the normalised ref"),
            }

    if kind == "boundary" and isinstance(m.get("to"), (int, float)) and m["to"] > m["cap"]:
        arg, cap = m["arg"], m["cap"]
        return {
            "rule": {"id": f"{tool.split('.')[-1].replace('_', '-')}-{arg.replace('_', '-')}-cap-{cap}",
                     "tools": [tool], "where": {arg: {"not_matches": range_regex(cap)}}, "verb": "BLOCK",
                     "reason": LIMIT_REASONS.get(arg, "Data minimisation") + f": 1 to {cap}"},
            "why": f"{arg}={m['to']} is above the cap of {cap}; block every value outside 1-{cap}",
        }

    if kind == "destination":
        arg = m["arg"]
        if arg == "order_id":
            where = {arg: {"not_in": TASK_ORDERS}}
            why = f"{arg}={m['to']} is not one of the incident's orders; only {', '.join(TASK_ORDERS)} are in scope"
        elif arg == "destination_account":
            where = {arg: {"matches": "."}}
            why = f"refund redirected to {m['to']}; refunds go back only to the payment method on file"
        else:
            where = {arg: {"equals": m["to"]}}
            why = f"{arg}={m['to']} is not the destination on file"
        return {"rule": {"id": f"{tool.split('.')[-1].replace('_', '-')}-{arg.replace('_', '-')}-on-file",
                         "tools": [tool], "where": where, "verb": "BLOCK", "reason": _real_reason(tool)},
                "why": why}

    if kind == "alias" and parent is not None:
        r = _rule_by_id(policy, parent.get("rule", ""))
        if r is not None and r.verb.value == "BLOCK":
            return {"rule": {"id": f"{r.id}-{tool.split('.')[-1].replace('_', '-')}", "tools": [tool],
                             **({"where": copy.deepcopy(r.where)} if r.where else {}),
                             "verb": "BLOCK", "reason": r.reason},
                    "why": f"`{tool}` does what `{dotted(parent['tool'])}` does; `{r.id}` must cover it too"}

    where = {k: {"equals": v} for k, v in gap["args"].items() if isinstance(v, (str, int, float)) and not isinstance(v, bool)}
    return {"rule": {"id": f"block-{gap['id']}", "tools": [tool], "where": where, "verb": "BLOCK",
                     "reason": _real_reason(tool, "Least privilege: a known-bad call")},
            "why": "no general rule fits; block this exact call"}


def same_rule(a: dict[str, Any], b: dict[str, Any]) -> bool:
    key = lambda r: (r["verb"], tuple(sorted(r["tools"])), yaml.safe_dump(r.get("where") or {}, sort_keys=True))
    return key(a) == key(b)


def write_policy(base_raw: dict[str, Any], rules: list[dict[str, Any]], path: Path, header: str) -> Policy:
    raw = copy.deepcopy(base_raw)
    raw["rules"] = [copy.deepcopy(r) for r in rules] + list(raw.get("rules") or [])
    raw["policy"] = f"{raw.get('policy', 'policy')}-evolved"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + yaml.safe_dump(raw, sort_keys=False, allow_unicode=True, width=120))
    return Policy.load(path)


def describe_where(where: dict[str, Any]) -> str:
    if not where:
        return "always"
    parts = []
    for arg, tests in where.items():
        for op, v in tests.items():
            parts.append(f"{arg} {op.replace('_', ' ')} {v}")
    return " and ".join(parts)


def checklist_line(p: dict[str, Any]) -> str:
    r = p["rule"]
    tools = ", ".join(runtime_name(t) for t in r["tools"])
    return f"[ ] {tools}: block when {describe_where(r.get('where') or {})}. Why: {p['why']}"

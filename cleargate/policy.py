from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cleargate.events import Verb


@dataclass(frozen=True)
class Verdict:
    verb: Verb
    rule: str
    reason: str
    approver: str | None = None


@dataclass(frozen=True)
class Rule:
    id: str
    verb: Verb
    tools: frozenset[str]
    agents: frozenset[str] | None = None
    where: dict[str, dict[str, Any]] = field(default_factory=dict)
    approver: str | None = None
    reason: str = ""

    def matches(self, agent: str, tool: str, args: dict[str, Any]) -> bool:
        if tool not in self.tools or (self.agents is not None and agent not in self.agents):
            return False
        return all(_check(args.get(key), tests) for key, tests in self.where.items())


OPERATORS = frozenset({"equals", "not_equals", "in", "not_in", "matches", "not_matches", "max"})


def _validate_where(rule_id: str, where: Any) -> dict[str, dict[str, Any]]:
    """Fail at load, not at the first matching call: a typo'd operator would otherwise raise
    KeyError mid-run or, worse, a rule that never matches would silently fall through."""
    if where is None:
        return {}
    if not isinstance(where, dict):
        raise ValueError(f"rule {rule_id}: `where` must map argument names to tests")
    for arg, tests in where.items():
        if not isinstance(tests, dict) or not tests:
            raise ValueError(f"rule {rule_id}: where.{arg} must be a mapping of operator: value")
        for op, expected in tests.items():
            if op not in OPERATORS:
                raise ValueError(f"rule {rule_id}: where.{arg} uses unknown operator {op!r}; "
                                 f"allowed: {', '.join(sorted(OPERATORS))}")
            if op in ("in", "not_in") and not isinstance(expected, list):
                raise ValueError(f"rule {rule_id}: where.{arg}.{op} needs a list")
            if op in ("matches", "not_matches"):
                try:
                    re.compile(str(expected))
                except re.error as exc:
                    raise ValueError(f"rule {rule_id}: where.{arg}.{op} is not a valid regex: {exc}") from exc
            if op == "max" and _number(expected) is None:
                raise ValueError(f"rule {rule_id}: where.{arg}.max needs a number, got {expected!r}")
    return where


def _check(value: Any, tests: dict[str, Any]) -> bool:
    text = "" if value is None else str(value)
    for op, expected in tests.items():
        ok = {
            "equals": lambda: text == str(expected),
            "not_equals": lambda: text != str(expected),
            "in": lambda: text in [str(e) for e in expected],
            "not_in": lambda: text not in [str(e) for e in expected],
            "matches": lambda: re.search(expected, text) is not None,
            "not_matches": lambda: re.search(expected, text) is None,
            "max": lambda: _number(value) is not None and _number(value) <= float(expected),
        }[op]()
        if not ok:
            return False
    return True


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class Policy:
    name: str
    source_path: str
    task_name: str
    task_intent: str
    visible_tools: tuple[str, ...]
    delegations: dict[str, tuple[str, ...]]
    write_tools: frozenset[str]
    rules: tuple[Rule, ...]
    default_verb: Verb
    default_reason: str
    agntid: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        raw = yaml.safe_load(Path(path).read_text())
        for r in raw.get("rules", []):
            if r["verb"] not in ("ALLOW", "BLOCK", "ESCALATE"):
                raise ValueError(f"rule {r['id']}: a call rule decides ALLOW, BLOCK or ESCALATE; NARROW is the visible_tools list")
        rules = tuple(
            Rule(
                id=r["id"],
                verb=Verb(r["verb"]),
                tools=frozenset(r["tools"]),
                agents=frozenset(r["agents"]) if "agents" in r else None,
                where=_validate_where(r["id"], r.get("where")),
                approver=r.get("approver"),
                reason=r.get("reason", ""),
            )
            for r in raw.get("rules", [])
        )
        return cls(
            name=raw["policy"],
            source_path=str(path),
            task_name=raw["task"]["name"],
            task_intent=raw["task"]["intent"],
            visible_tools=tuple(raw.get("visible_tools", [])),
            agntid=raw.get("agntid", {}),
            delegations={k: tuple(v or []) for k, v in raw.get("delegations", {}).items()},
            write_tools=frozenset(raw.get("write_tools", [])),
            rules=rules,
            default_verb=Verb(raw.get("default", {}).get("verb", "BLOCK")),
            default_reason=raw.get("default", {}).get("reason", "no rule allows the call"),
        )

    def constraints_for(self, agent: str) -> tuple[str, ...]:
        return self.delegations.get(agent, ())

    def evaluate(self, agent: str, tool: str, args: dict[str, Any], constraints: tuple[str, ...] = ()) -> Verdict:
        if self.visible_tools and tool not in self.visible_tools:
            return Verdict(Verb.BLOCK, "visible_tools", f"{tool} was narrowed out of this task")
        if "read-only" in constraints and tool in self.write_tools:
            return Verdict(Verb.BLOCK, "delegation:read-only",
                           f"{agent} was delegated read-only; {tool} changes state")
        for rule in self.rules:
            if rule.matches(agent, tool, args):
                return Verdict(rule.verb, rule.id, rule.reason or rule.id.replace("-", " "), rule.approver)
        return Verdict(self.default_verb, "default", self.default_reason)


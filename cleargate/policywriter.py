"""Least-privilege policy writer: learn the AgntID policy from what the agent team actually needed.

    python -m cleargate.policywriter propose --record records/<run>-gated.jsonl \
        [--attacks records/attacks-<ts>.json] [--out policies/proposed-<ts>] [--policy policy.yaml] [--offline]

AgntID's CLI module does observe -> promote -> write rules for shell commands. This does the same for MCP
tools: it reads a signed run record, keeps the in-task calls made by the legit sub-agents, and proposes the
tightest portal configuration that still lets every one of them through (protection profile, per-tool
disables, Baseline Allow Policy input limits, escalations). Every line carries its real-world reason and
the record evidence (seq numbers and args digests). A shadow replay re-evaluates every recorded call, and
every attack if given, against the proposal with the local stand-in evaluator (cleargate.policy).
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import os
import re
import sys
import time
import warnings
from collections import defaultdict
from pathlib import Path
from typing import Any

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*authlib.jose.*")

import yaml

from cleargate.canonical import arguments_digest
from cleargate.config import ROOT
from cleargate.events import Kind, Verb
from cleargate.policy import Policy, Verdict
from cleargate.record import read_record
from cleargate.tools.base import dotted, runtime_name

PROFILES = ("High", "Medium", "Low")
PROFILE_ALLOWS = {"High": {"read"}, "Medium": {"read", "write"}, "Low": {"read", "write", "destructive"}}
PROFILE_TEXT = {
    "High": "only reviewed read and list actions",
    "Medium": "reviewed read and normal-write actions; delete, execute and high-impact actions stay hidden",
    "Low": "all reviewed actions unless a policy blocks them",
}
LEGIT_AGENTS = {"triage", "database", "db", "fix", "comms"}
MCP_ENDPOINTS = {"payments": "http://localhost:9101/mcp", "comms": "http://localhost:9102/mcp"}
GITHUB_MCP = "https://api.githubcopilot.com/mcp/"

# Snapshot of the official GitHub remote MCP (default toolsets, list_tools on 2026-10-10):
# name -> (readOnlyHint, destructiveHint). Used when the live listing is unavailable.
GITHUB_SNAPSHOT: dict[str, tuple[bool, bool]] = {
    **{n: (True, False) for n in (
        "get_commit", "get_file_contents", "get_label", "get_latest_release", "get_me", "get_release_by_tag",
        "get_tag", "get_team_members", "get_teams", "issue_read", "list_branches", "list_commits",
        "list_issue_fields", "list_issue_types", "list_issues", "list_pull_requests", "list_releases",
        "list_repository_collaborators", "list_tags", "pull_request_read", "run_secret_scanning", "search_code",
        "search_commits", "search_issues", "search_pull_requests", "search_repositories", "search_users",
        "ui_get")},
    **{n: (False, False) for n in (
        "add_comment_to_pending_review", "add_issue_comment", "add_reply_to_pull_request_comment", "create_branch",
        "create_or_update_file", "create_pull_request", "create_repository", "fork_repository", "issue_write",
        "merge_pull_request", "pull_request_review_write", "push_files", "request_copilot_review",
        "sub_issue_write", "update_issue_comment", "update_pull_request", "update_pull_request_branch")},
    "delete_file": (False, True),
}
# Same shape for our own servers (mirrors cleargate/mcp/*.py annotations and tags).
STATIC_OWN: dict[str, tuple[bool, bool, tuple[str, ...]]] = {
    "payments.query_refunds": (True, False, ()),
    "payments.get_order": (True, False, ()),
    "payments.issue_refund": (False, False, ()),
    "payments.export_customer_records": (False, True, ("export", "high-impact", "pii")),
    "payments.run_sql": (False, True, ("admin", "execute", "high-impact")),
    "comms.post_incident_update": (False, False, ()),
    "comms.post_message": (False, False, ()),
    "comms.send_email": (False, False, ("exfiltration-risk", "external")),
}
STATIC_SCHEMAS: dict[str, dict[str, str]] = {
    "payments.query_refunds": {"order_id": "string", "limit": "integer"},
    "payments.get_order": {"order_id": "string"},
    "payments.issue_refund": {"order_id": "string", "amount_inr": "integer"},
    "payments.export_customer_records": {"segment": "string"},
    "payments.run_sql": {"sql": "string"},
    "comms.post_incident_update": {"text": "string"},
    "comms.post_message": {"channel": "string", "text": "string"},
    "comms.send_email": {"to": "string", "subject": "string", "body": "string"},
}

# Quantity-like inputs get a Minimum/Maximum; identifiers (pull_number, issue_number) do not.
QUANTITY_CAPS = {"limit": 100, "max_rows": 100, "per_page": 100, "perPage": 100, "amount_inr": 5000}
LADDER = (1, 2, 5, 10, 20, 25, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000)
ESCALATE_TOOLS = {"github.merge_pull_request"}

# A generic tool the run never needed, and the narrow tool that does the legit part of its job.
NARROW_INSTEAD = {
    "comms.post_message": "comms.post_incident_update",
    "payments.run_sql": "payments.query_refunds / payments.get_order",
    "github.push_files": "github.create_or_update_file on a fix/ branch",
    "github.issue_write": "github.add_issue_comment (if a comment is ever needed)",
}

R_LEAST = "Least privilege (ISO 27001 A.5.15 / PCI DSS Req 7.2): the team never needed it for this task"
R_CHANGE = ("Change management (PCI DSS Req 6.5 / RBI IT governance): no repo-changing tool beyond the "
            "branch -> PR -> approved merge path")
REASONS = {
    "payments.export_customer_records": "PCI DSS Req 3 and 7 / DPDP s.6 purpose limitation: card-holder data is "
                                        "never bulk-exported to fix an incident",
    "payments.run_sql": "PCI DSS Req 7 / least privilege: raw SQL bypasses every bounded read; never needed",
    "payments.issue_refund": "RBI maker-checker: per-agent refund ceiling INR 5,000; the incident needed no refund",
    "comms.send_email": "DPDP Act s.8 security safeguards: email to outside domains is the exfiltration path",
    "comms.post_message": "Incident comms policy / DPDP purpose limitation: updates go only to #inc-4471",
    "github.merge_pull_request": "RBI maker-checker / segregation of duties: the agent proposes, a named "
                                 "engineer approves this exact merge (args digest)",
    "github.delete_file": R_CHANGE,
    "github.push_files": R_CHANGE,
}
LIMIT_REASONS = {
    "limit": "DPDP Act s.6 data minimisation: bounded refund reads",
    "max_rows": "DPDP Act s.6 data minimisation: bounded reads",
    "per_page": "Data minimisation: bounded listings",
    "perPage": "Data minimisation: bounded listings",
    "amount_inr": "RBI maker-checker: per-agent refund ceiling",
}


def _klass(read_only: bool | None, destructive: bool | None, tags: tuple[str, ...] | list[str] = ()) -> str:
    if destructive or {"high-impact", "execute"} & set(tags):
        return "destructive"
    return "read" if read_only else "write"


def _guess_klass(tool: str) -> str:
    bare = tool.split(".", 1)[-1]
    if re.match(r"(get|list|search|read|query)_", bare) or bare.endswith("_read"):
        return "read"
    if re.match(r"(delete|drop|run|exec)_", bare):
        return "destructive"
    return "write"


async def _list_live(url: str, headers: dict[str, str] | None = None) -> list[Any]:
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    async with Client(StreamableHttpTransport(url, headers=headers or {})) as client:
        return await client.list_tools()


def load_catalog(offline: bool = False) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    catalog: dict[str, dict[str, Any]] = {}
    sources: dict[str, str] = {}

    def add(server: str, tool: Any) -> None:
        a = tool.annotations
        tags = tuple(((tool.meta or {}).get("_fastmcp") or {}).get("tags") or ())
        props = (tool.inputSchema or {}).get("properties") or {}
        catalog[f"{server}.{tool.name}"] = {
            "class": _klass(a.readOnlyHint if a else None, a.destructiveHint if a else None, tags),
            "annotations": a.model_dump(exclude_none=True) if a else {}, "tags": list(tags),
            "schema": {k: v.get("type", "") for k, v in props.items()}, "source": "live"}

    async def fetch(server: str, url: str, headers: dict[str, str] | None = None) -> None:
        tools = await asyncio.wait_for(_list_live(url, headers), 15)
        for t in tools:
            add(server, t)
        sources[server] = f"live list_tools {url} ({len(tools)} tools)"

    async def gather() -> None:
        jobs = {s: fetch(s, u) for s, u in MCP_ENDPOINTS.items()}
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN")
        if token:
            jobs["github"] = fetch("github", GITHUB_MCP, {"Authorization": f"Bearer {token}"})
        results = await asyncio.gather(*jobs.values(), return_exceptions=True)
        for server, res in zip(jobs, results):
            if isinstance(res, BaseException):
                sources[server] = f"static map (live list_tools failed: {type(res).__name__})"

    if not offline:
        try:
            asyncio.run(gather())
        except Exception as exc:  # noqa: BLE001
            sources.setdefault("_", f"live discovery failed: {exc}")

    for name, (ro, de, tags) in STATIC_OWN.items():
        server = name.split(".")[0]
        if not any(k.startswith(server + ".") and catalog[k]["source"] == "live" for k in catalog):
            catalog[name] = {"class": _klass(ro, de, tags), "annotations": {"readOnlyHint": ro, "destructiveHint": de},
                             "tags": list(tags), "schema": STATIC_SCHEMAS.get(name, {}), "source": "static"}
            sources.setdefault(server, "static map (offline)")
    if not any(k.startswith("github.") for k in catalog):
        for bare, (ro, de) in GITHUB_SNAPSHOT.items():
            catalog[f"github.{bare}"] = {"class": _klass(ro, de), "annotations": {"readOnlyHint": ro,
                                         "destructiveHint": de}, "tags": [], "schema": {}, "source": "snapshot"}
        sources.setdefault("github", f"snapshot of the official GitHub MCP ({len(GITHUB_SNAPSHOT)} tools)")
    sources.pop("_", None)
    return catalog, sources


@dataclasses.dataclass
class Call:
    seq: int
    agent: str
    tool: str
    args: dict[str, Any]
    args_digest: str
    verb: str
    rule: str
    outside: bool
    executed: bool
    approver: str | None
    late: bool
    needed: bool = False

    def evidence(self) -> str:
        return f"#{self.seq} {self.agent} {self.args_digest[:12]}"


def observe(entries: list[dict[str, Any]], base: Policy) -> tuple[dict[str, Any], list[Call]]:
    header = entries[0]["payload"] if entries and entries[0]["payload"].get("kind") == "header" else {}
    calls: list[Call] = []
    late = False
    for e in entries:
        p = e["payload"]
        if p.get("kind") == Kind.TASK_CLOSE:
            late = True
        if p.get("kind") != Kind.CALL:
            continue
        tool, args = dotted(p["tool"]), dict(p.get("args") or {})
        outside, verb, rule = bool(p.get("outside_task")), str(p["verb"]), p.get("rule", "")
        c = Call(e["seq"], p["agent"], tool, args, e.get("args_digest") or arguments_digest(args), verb,
                 rule, outside, bool(p.get("executed")), p.get("approver"), late)
        if c.outside and not c.late and c.verb == Verb.UNGUARDED and rule != "approval-evidence":
            # Stock run: an escalate-class call (the merge) ran with no approver, so the mirror flags it
            # out of task. The work itself was in scope; it needs a checker, not a ban.
            c.outside = base.evaluate(c.agent, c.tool, c.args, base.constraints_for(c.agent)).verb != Verb.ESCALATE
        c.needed = (not c.outside and not c.late and c.agent in LEGIT_AGENTS
                    and c.verb in (Verb.ALLOW, Verb.ESCALATE, Verb.UNGUARDED))
        calls.append(c)
    return header, calls


def nice_ceiling(value: float, cap: int) -> int:
    for step in LADDER:
        if step >= value:
            return min(step, cap)
    return cap


def propose(calls: list[Call], catalog: dict[str, dict[str, Any]]) -> dict[str, Any]:
    needed: dict[str, list[Call]] = defaultdict(list)
    for c in calls:
        if c.needed:
            needed[c.tool].append(c)
    for tool in needed:
        catalog.setdefault(tool, {"class": _guess_klass(tool), "annotations": {}, "tags": [], "schema": {},
                                  "source": "not in the live catalog (named in the record)"})

    needed_classes = {catalog[t]["class"] for t in needed}
    profile = next(p for p in PROFILES if needed_classes <= PROFILE_ALLOWS[p])
    under_profile = sorted(t for t, m in catalog.items() if m["class"] in PROFILE_ALLOWS[profile])
    hidden_by_profile = sorted(t for t in catalog if t not in under_profile)
    disable = []
    for t in under_profile:
        if t in needed:
            continue
        reason = REASONS.get(t) or (R_CHANGE if t.startswith("github.") and catalog[t]["class"] != "read" else R_LEAST)
        item = {"tool": t, "runtime_name": runtime_name(t), "class": catalog[t]["class"], "reason": reason,
                "evidence": "0 in-task calls in the record"}
        if t in NARROW_INSTEAD:
            item["use_instead"] = NARROW_INSTEAD[t]
        disable.append(item)

    limits = []
    for tool, cs in sorted(needed.items()):
        schema = catalog[tool].get("schema") or {}
        params = {k for c in cs for k, v in c.args.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}
        params |= {k for k, typ in schema.items() if typ in ("integer", "number")}
        for param in sorted(params):
            if param not in QUANTITY_CAPS:
                continue
            values = [c.args[param] for c in cs if isinstance(c.args.get(param), (int, float))]
            cap = QUANTITY_CAPS[param]
            hi = nice_ceiling(max(values), cap) if values else cap
            limits.append({
                "tool": tool, "input": param, "minimum": 1, "maximum": hi,
                "observed": {"min": min(values), "max": max(values), "n": len(values)} if values else None,
                "reason": LIMIT_REASONS.get(param, "Data minimisation"),
                "evidence": [c.evidence() for c in cs if param in c.args] or ["schema only (not passed in the run)"],
                "warning": (f"observed {max(values)} exceeds the policy ceiling {cap}" if values and max(values) > cap
                            else ""),
            })

    escalate = []
    for tool, cs in sorted(needed.items()):
        observed = [c for c in cs if c.verb == Verb.ESCALATE or c.approver
                    or (c.verb == Verb.UNGUARDED and c.rule.startswith("merge"))]
        if observed or tool in ESCALATE_TOOLS:
            escalate.append({"tool": tool, "runtime_name": runtime_name(tool), "approver": "platform-engineer",
                             "reason": REASONS.get(tool, "Segregation of duties"),
                             "evidence": [c.evidence() + (f" approved by {c.approver}" if c.approver else "")
                                          for c in (observed or cs)]})

    keep = [{"tool": t, "runtime_name": runtime_name(t), "class": catalog[t]["class"],
             "calls": len(cs), "agents": sorted({c.agent for c in cs}), "evidence": [c.evidence() for c in cs]}
            for t, cs in sorted(needed.items())]

    notes = []
    for t in ("payments.issue_refund",):
        if t not in needed and t in catalog:
            notes.append(f"{t} is disabled because the run never refunded. If a corrective refund becomes part of "
                         "the runbook, re-enable it with amount_inr Minimum 1, Maximum 5000 (RBI maker-checker).")
    for c in calls:
        if c.tool == "github.create_or_update_file" and c.needed and "branch" in c.args:
            notes.append("Branch constraint (string, not a portal min/max): every needed github.create_or_update_file "
                         "wrote to a fix/ branch; ClearGate keeps the app-layer rule `never-write-to-main` "
                         "(PCI DSS Req 6.5 change management).")
            break

    return {"profile": profile, "profile_text": PROFILE_TEXT[profile], "needed_classes": sorted(needed_classes),
            "catalog_size": len(catalog), "visible_under_profile": len(under_profile),
            "hidden_by_profile": hidden_by_profile, "keep": keep, "disable": disable, "limits": limits,
            "escalate": escalate, "visible_after": sorted(needed), "notes": notes}


class ProposedEvaluator:
    """Portal layer (profile, per-tool disable, input min/max) first, then ClearGate's app-layer rules."""

    def __init__(self, base: Policy, proposal: dict[str, Any], catalog: dict[str, dict[str, Any]]):
        self.visible = set(proposal["visible_after"])
        self.disabled = {d["tool"] for d in proposal["disable"]}
        self.limits = {(lim["tool"], lim["input"]): lim for lim in proposal["limits"]}
        self.catalog = catalog
        visible = tuple(sorted(self.visible | set(base.visible_tools)))
        self.policy = dataclasses.replace(base, visible_tools=visible)
        self.base = base

    def portal(self, tool: str, args: dict[str, Any]) -> Verdict | None:
        if tool not in self.visible:
            how = ("disabled individually" if tool in self.disabled else
                   "hidden by the protection profile" if tool in self.catalog else "not in any server catalog")
            return Verdict(Verb.BLOCK, "portal:hidden", f"{tool} {how}")
        for (t, param), lim in self.limits.items():
            if t != tool or param not in args:
                continue
            try:
                v = float(args[param])
            except (TypeError, ValueError):
                return Verdict(Verb.BLOCK, "portal:input-limit", f"{param} is not a number")
            if not lim["minimum"] <= v <= lim["maximum"]:
                return Verdict(Verb.BLOCK, "portal:input-limit",
                               f"{param}={args[param]} outside {lim['minimum']}-{lim['maximum']}")
        return None

    def evaluate(self, agent: str, tool: str, args: dict[str, Any]) -> Verdict:
        return self.portal(tool, args) or self.policy.evaluate(agent, tool, args, self.base.constraints_for(agent))


def shadow_record(calls: list[Call], base: Policy, ev: ProposedEvaluator) -> dict[str, Any]:
    rows = []
    for c in calls:
        if c.approver:
            continue  # the post-approval execution of an ESCALATE already counted
        before = base.evaluate(c.agent, c.tool, c.args, base.constraints_for(c.agent))
        after = ev.evaluate(c.agent, c.tool, c.args)
        if c.late:  # after task close the delegation is gone; the lifecycle stops it before any policy runs
            closed = Verdict(Verb.BLOCK, "task-closed", "call after the task closed")
            before, after = closed, closed
        ok = after.verb in (Verb.ALLOW, Verb.ESCALATE)
        rows.append({"seq": c.seq, "agent": c.agent, "tool": c.tool, "args_digest": c.args_digest, "needed": c.needed,
                     "late": c.late, "before": str(before.verb), "before_rule": before.rule,
                     "after": str(after.verb), "after_rule": after.rule, "after_reason": after.reason,
                     "flipped": before.verb != after.verb, "broken": c.needed and not ok})
    return {"calls": rows, "needed": sum(r["needed"] for r in rows),
            "needed_broken": sum(r["broken"] for r in rows), "flipped": sum(r["flipped"] for r in rows),
            "out_of_task": sum(not r["needed"] for r in rows),
            "out_of_task_stopped": sum(not r["needed"] and r["after"] != Verb.ALLOW for r in rows)}


def _results(section: Any) -> list[dict[str, Any]]:
    if isinstance(section, list):
        return section
    return (section or {}).get("results") or []


def shadow_attacks(path: Path, base: Policy, ev: ProposedEvaluator) -> dict[str, Any]:
    data = json.loads(path.read_text())
    catalog = yaml.safe_load((ROOT / "attacks" / "catalog.yaml").read_text())
    args_by_id = {a["id"]: a for a in catalog.get("attacks", [])}
    results = _results(data.get("agntid")) or _results(data.get("stock"))
    ids = [r["id"] for r in results] or list(args_by_id)
    agents = sorted(LEGIT_AGENTS - {"db"})
    rows = []
    for aid in ids:
        a = args_by_id.get(aid)
        if not a:
            continue
        tool, args = dotted(a["tool"]), dict(a.get("args") or {})

        def worst(fn: Any) -> Verdict:
            verdicts = [fn(agent) for agent in agents]
            return next((v for v in verdicts if v.verb == Verb.ALLOW), None) or \
                next((v for v in verdicts if v.verb == Verb.ESCALATE), verdicts[0])

        before = worst(lambda ag: base.evaluate(ag, tool, args, base.constraints_for(ag)))
        portal = ev.portal(tool, args)
        after = worst(lambda ag: ev.evaluate(ag, tool, args))
        rows.append({"id": aid, "tool": tool, "args_digest": arguments_digest(args), "owasp": a.get("owasp"),
                     "before": str(before.verb), "after": str(after.verb), "after_rule": after.rule,
                     "portal_only": "BLOCK" if portal else "PASS", "portal_rule": portal.rule if portal else ""})
    stopped = lambda key: sum(r[key] != Verb.ALLOW for r in rows)  # noqa: E731
    return {"source": str(path), "attacks": rows, "total": len(rows),
            "blocked_before": stopped("before"), "blocked_after": stopped("after"),
            "blocked_by_portal_alone": sum(r["portal_only"] == "BLOCK" for r in rows)}


def diff_current(base: Policy, proposal: dict[str, Any]) -> dict[str, Any]:
    cur = set(base.visible_tools)
    new = set(proposal["visible_after"])
    cur_limits = sorted({f"{t}.{k}" for r in base.rules if r.where for t in r.tools for k in r.where})
    cur_escalate = sorted({t for r in base.rules if r.verb == Verb.ESCALATE for t in r.tools})
    return {"catalog_size": proposal["catalog_size"], "visible_under_profile": proposal["visible_under_profile"],
            "visible_proposed": len(new), "policy_yaml_visible": len(cur),
            "added_vs_policy_yaml": sorted(new - cur), "removed_vs_policy_yaml": sorted(cur - new),
            "limits_current": cur_limits,
            "limits_proposed": [f"{lim['tool']}.{lim['input']} {lim['minimum']}-{lim['maximum']}" for lim in proposal["limits"]],
            "escalate_current": cur_escalate, "escalate_proposed": [e["tool"] for e in proposal["escalate"]]}


def summary_line(d: dict[str, Any], rec: dict[str, Any], att: dict[str, Any] | None) -> str:
    parts = [f"{d['catalog_size']} catalog tools -> {d['visible_under_profile']} under profile -> "
             f"{d['visible_proposed']} visible", f"{len(d['limits_proposed'])} parameter limit(s)",
             ("merge escalates" if "github.merge_pull_request" in d["escalate_proposed"] else
              f"{len(d['escalate_proposed'])} escalation(s)"),
             f"{rec['needed_broken']} needed calls broken (of {rec['needed']})",
             f"{rec['out_of_task_stopped']}/{rec['out_of_task']} out-of-task calls stopped"]
    if att:
        parts.append(f"{att['blocked_after']}/{att['total']} attacks blocked "
                     f"({att['blocked_by_portal_alone']} by the portal config alone; {att['blocked_before']} before)")
    return "; ".join(parts)


def render_md(meta: dict[str, Any], p: dict[str, Any], d: dict[str, Any], rec: dict[str, Any],
              att: dict[str, Any] | None) -> str:
    L: list[str] = []
    w = L.append
    w(f"# Proposed AgntID policy: {meta['policy']} (learned from run {meta['run_id']})\n")
    w(f"Generated {meta['generated']} from `{meta['record']}` ({meta['mode']} record). "
      "Nothing is applied until an engineer clicks it in. Tick each box as you set it in the portal.\n")
    w(f"**Summary:** {summary_line(d, rec, att)}.\n")
    w("Catalog sources: " + "; ".join(f"{k}: {v}" for k, v in sorted(meta["sources"].items())) + "\n")

    w("## 1. Setup → Protection Profile\n")
    w(f"- [ ] Runtime → **Setup** → **Protection Profile** → select **{p['profile']}** and mark it reviewed.")
    w(f"  - What it allows: {p['profile_text']}.")
    w(f"  - Why: the team's needed tools are of class {', '.join(p['needed_classes'])}; {p['profile']} is the "
      "tightest profile that still allows all of them.")
    if p["hidden_by_profile"]:
        w(f"  - Hidden by the profile alone ({len(p['hidden_by_profile'])}): "
          + ", ".join(f"`{t}`" for t in p["hidden_by_profile"]))
    hi = [t for t in p["hidden_by_profile"] if t == "payments.export_customer_records"]
    if hi:
        w(f"- [ ] Access Control → **Advanced** → Action Classifications → confirm `{hi[0]}` is high impact "
          f"(pin it). Reason: {REASONS[hi[0]]}.")
    w("")

    w("## 2. Access Control → Tools: disable individually\n")
    w(f"Visible under {p['profile']} but never needed in the run. Disable each one.\n")
    for item in p["disable"]:
        extra = f" Use `{item['use_instead']}` instead." if item.get("use_instead") else ""
        w(f"- [ ] `{item['tool']}` ({item['class']}): {item['reason']}.{extra} Evidence: {item['evidence']}.")
    w("")

    w("## 3. Access Policies → tool → Baseline Allow Policy (input limits)\n")
    if not p["limits"]:
        w("- No quantity inputs observed on the needed tools.")
    for lim in p["limits"]:
        server = lim["tool"].split(".")[0]
        obs = lim["observed"]
        seen = f"observed {obs['min']}-{obs['max']} over {obs['n']} call(s)" if obs else "not passed in the run"
        w(f"- [ ] Access Policies → `{server}` → `{lim['tool']}` → **Baseline Allow Policy** → input `{lim['input']}` "
          f"Minimum **{lim['minimum']}**, Maximum **{lim['maximum']}** → Save → wait for Runtime sync: Applied.")
        w(f"  - Why: {lim['reason']}; {seen}. Evidence: {', '.join(lim['evidence'])}.")
        if lim["warning"]:
            w(f"  - WARNING: {lim['warning']}.")
    w("")

    w("## 4. Escalations (runtime deny + human approval at the app layer)\n")
    for e in p["escalate"]:
        w(f"- [ ] `{e['tool']}`: keep visible, no baseline allow for the agent's direct call (runtime denies); "
          f"ClearGate escalates to **{e['approver']}** and binds the approval to the args digest.")
        w(f"  - Why: {e['reason']}. Evidence: {', '.join(e['evidence'])}.")
    w("")

    w("## 5. Keep (the tools the team actually needed)\n")
    for k in p["keep"]:
        w(f"- `{k['tool']}` ({k['class']}), {k['calls']} call(s) by {', '.join(k['agents'])}: {', '.join(k['evidence'])}")
    w("")

    if p["notes"]:
        w("## Notes\n")
        for n in p["notes"]:
            w(f"- {n}")
        w("")

    w("## Diff vs policy.yaml\n")
    w(f"- Tools visible: {d['catalog_size']} in the catalog → {d['visible_under_profile']} under {p['profile']} → "
      f"**{d['visible_proposed']}** proposed (policy.yaml lists {d['policy_yaml_visible']}).")
    w(f"- Added vs policy.yaml: {', '.join(d['added_vs_policy_yaml']) or 'none'}")
    w(f"- Removed vs policy.yaml (never needed): {', '.join(d['removed_vs_policy_yaml']) or 'none'}")
    w(f"- Parameter limits: current {', '.join(d['limits_current']) or 'none'} → proposed "
      f"{', '.join(d['limits_proposed']) or 'none'}")
    w(f"- Escalations: current {', '.join(d['escalate_current']) or 'none'} → proposed "
      f"{', '.join(d['escalate_proposed']) or 'none'}\n")

    w("## Shadow replay (local stand-in evaluator, not AgntID)\n")
    w(f"**{rec['needed_broken']} needed calls broken** (of {rec['needed']}); {rec['flipped']} call(s) flip vs "
      f"policy.yaml; {rec['out_of_task_stopped']}/{rec['out_of_task']} out-of-task calls stopped.\n")
    w("| seq | agent | tool | needed | policy.yaml | proposed | rule |")
    w("|---|---|---|---|---|---|---|")
    for r in rec["calls"]:
        flip = " (flip)" if r["flipped"] else ""
        w(f"| {r['seq']} | {r['agent']} | `{r['tool']}`{' (late)' if r['late'] else ''} | "
          f"{'yes' if r['needed'] else 'no'} | {r['before']} | {r['after']}{flip} | {r['after_rule']} |")
    w("")
    if att:
        w(f"### Attacks ({att['source']})\n")
        w(f"**{att['blocked_after']}/{att['total']} attacks blocked** under the proposal "
          f"({att['blocked_by_portal_alone']} by the portal config alone); {att['blocked_before']} under policy.yaml.\n")
        w("| attack | tool | policy.yaml | proposed | portal alone |")
        w("|---|---|---|---|---|")
        for r in att["attacks"]:
            w(f"| {r['id']} | `{r['tool']}` | {r['before']} | {r['after']} ({r['after_rule']}) | "
              f"{r['portal_only']} {r['portal_rule']} |")
        w("")
        w("A visible, needed tool whose arguments are free text (e.g. an injected `comms.post_incident_update`) "
          "is left to AgntID's LLM-based intent check; min/max limits cannot express it.")
        w("")
    return "\n".join(L)


def run_propose(record: Path, attacks: Path | None, out: Path | None, policy_path: Path,
                offline: bool = False) -> dict[str, Any]:
    base = Policy.load(policy_path)
    entries = read_record(record)
    header, calls = observe(entries, base)
    catalog, sources = load_catalog(offline)
    proposal = propose(calls, catalog)
    ev = ProposedEvaluator(base, proposal, catalog)
    rec = shadow_record(calls, base, ev)
    att = shadow_attacks(attacks, base, ev) if attacks else None
    d = diff_current(base, proposal)
    limits_by_tool: dict[str, dict[str, Any]] = defaultdict(dict)
    for x in proposal["limits"]:
        limits_by_tool[x["tool"]][x["input"]] = {"minimum": x["minimum"], "maximum": x["maximum"]}
    ts = time.strftime("%Y%m%d-%H%M%S")
    out = out or ROOT / "policies" / f"proposed-{ts}"
    out.parent.mkdir(parents=True, exist_ok=True)
    meta = {"generated": ts, "record": str(record), "run_id": header.get("run_id", record.stem),
            "mode": header.get("mode", "?"), "policy": base.name, "policy_path": str(policy_path),
            "attacks": str(attacks) if attacks else None, "sources": sources}
    doc = {"meta": meta, "summary": summary_line(d, rec, att), "proposal": proposal, "diff": d,
           "shadow": {"record": rec, "attacks": att},
           "portal": {"protection_profile": proposal["profile"],
                      "disable": [x["runtime_name"] for x in proposal["disable"]],
                      "baseline_allow_limits": limits_by_tool,
                      "escalate": [x["runtime_name"] for x in proposal["escalate"]]}}
    out.with_suffix(".json").write_text(json.dumps(doc, indent=2, default=str))
    out.with_suffix(".md").write_text(render_md(meta, proposal, d, rec, att))
    doc["paths"] = [str(out.with_suffix(".md")), str(out.with_suffix(".json"))]
    return doc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cleargate.policywriter", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("propose", help="propose a least-privilege AgntID policy from a signed run record")
    pp.add_argument("--record", type=Path, help="gated or stock record (default: latest gated)")
    pp.add_argument("--attacks", type=Path, help="attack-suite output records/attacks-<ts>.json")
    pp.add_argument("--out", type=Path, help="output prefix, e.g. policies/proposed-<ts>")
    pp.add_argument("--policy", type=Path, default=ROOT / "policy.yaml")
    pp.add_argument("--offline", action="store_true", help="skip live list_tools; use the static maps")
    args = ap.parse_args(argv)
    record = args.record or max((ROOT / "records").glob("*-gated.jsonl"), default=None)
    if record is None:
        raise SystemExit("no record; run `cleargate check --stub --quiet` first")
    doc = run_propose(record, args.attacks, args.out, args.policy, args.offline)
    p = doc["proposal"]
    print(f"record   {record}")
    print(f"profile  {p['profile']}  ({p['profile_text']})")
    print(f"keep     {', '.join(p['visible_after'])}")
    print(f"disable  {len(p['disable'])} tool(s): {', '.join(x['tool'] for x in p['disable'][:8])}"
          + (" ..." if len(p["disable"]) > 8 else ""))
    for lim in p["limits"]:
        print(f"limit    {lim['tool']}.{lim['input']} {lim['minimum']}-{lim['maximum']}")
    for e in p["escalate"]:
        print(f"escalate {e['tool']} -> {e['approver']}")
    print(f"summary  {doc['summary']}")
    for path in doc["paths"]:
        print(f"wrote    {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

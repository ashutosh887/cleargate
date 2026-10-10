"""Evidence pack: a go-live decision an engineer can hand to audit, verifiable offline.

    python -m cleargate.evidence --record records/<run>-gated.jsonl [--stock <stock.jsonl>]
        [--attacks records/attacks-<ts>.json] [--policy <proposal.json>] [--out evidence/<run_id>/]
        [--inject-claim "<sentence>"]
    python -m cleargate.evidence verify evidence/<run_id>/

The go-live report is drafted by the configured LLM (CLEARGATE_LLM=openai|bedrock|anthropic) or, by
default, a deterministic template; either way cleargate.claims drops every sentence the record does
not support. --inject-claim adds a sentence to the draft to show the checker at work.

The pack folder holds index.html (print-friendly decision record), the signed record(s), the
public key, verify.py, the policy file, any attack/proposal inputs, and manifest.json: every file
with its SHA-256, signed with the record's own Ed25519 key over the canonical JSON of the manifest.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import importlib.util
import json
import shutil
import string
import sys
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from cleargate.canonical import canonical_json
from cleargate.claims import Claim, RecordFacts, check_draft
from cleargate.config import ROOT, Settings
from cleargate.record import load_or_create_key, public_key_fingerprint, read_record

TEMPLATES = Path(__file__).parent / "evidence_templates"
MANIFEST = "manifest.json"
PUBKEY = "signing_pub.pem"
WRITE_TO_MAIN = ("create_or_update_file", "push_files", "delete_file")

CONTROL_NAMES = {
    "visible_tools": "Tool visibility (narrowed out of the task)",
    "policy_evaluation": "Per-tool / parameter policy",
    "delegation": "Delegation constraint (read-only sub-agent)",
    "approval": "Approval bound to the arguments digest",
    "task_resolution": "Just-for-task: task closed",
    "intent": "Intent check",
}

AGNTID, STAND_IN, APP, BANK = "AgntID runtime", "Local stand-in (not AgntID)", "ClearGate app layer", "Bank system"
DECIDERS = {
    AGNTID: ("d-agntid", "the AgntID runtime decided over MCP"),
    STAND_IN: ("d-local", "ClearGate's local policy.yaml evaluator standing in for AgntID; rows staged "
                          "local-simulation approximate an AgntID control"),
    APP: ("d-app", "ClearGate's own layer: approval capture and digest binding, task notices, sandbox guard, transport"),
    BANK: ("d-bank", "the core-banking system refused the call itself (payee check inside refund_to_account)"),
}
APP_STEPS = {"live_sandbox_guard", "transport"}
READ_PREFIXES = ("get_", "list_", "query_", "search_", "read_")

e = html.escape


def decider_of(row: dict[str, Any]) -> str:
    """Who made this decision, from the record's stage / denial_step / source fields."""
    meta = row.get("meta") or {}
    stage = str(row.get("stage") or meta.get("stage") or row.get("denial_step") or "")
    reason = str(row.get("reason") or "")
    if stage.startswith("bank-system"):
        return BANK
    if stage.startswith("local-simulation") or reason.startswith("[local-simulation"):
        return STAND_IN
    if row.get("kind") in ("approval", "notice") or stage in APP_STEPS or reason.startswith("approval is not a bypass"):
        return APP
    source = str(row.get("source") or "").lower()
    if source == "agntid":
        return AGNTID
    if "stand-in" in source or "not agntid" in source:
        return STAND_IN
    return APP


def stage_of(row: dict[str, Any]) -> str:
    meta = row.get("meta") or {}
    return str(row.get("stage") or meta.get("stage") or row.get("denial_step") or "")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def load_verifier() -> Callable[[Path, Path], tuple[bool, str]]:
    spec = importlib.util.spec_from_file_location("cleargate_verify", ROOT / "verify.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify



class RunView:
    """A signed record read back as header + decisions, plus the counts and verdict derived from it."""

    def __init__(self, path: Path):
        self.path = path
        self.entries = read_record(path)
        self.header = self.entries[0]["payload"]
        self.rows = [dict(en["payload"], seq=en["seq"], line_digest=en.get("args_digest", "")) for en in self.entries[1:]]
        self.final_hash = self.entries[-1]["hash"]
        last = path.read_text(encoding="utf-8").rstrip().rsplit("\n", 1)[-1]
        self.seal = (json.loads(last).get("payload") or {}) if last else {}
        if self.seal.get("kind") != "seal":
            self.seal = {}
        self.mode = self.header.get("mode", "?")
        self.run_id = self.header.get("run_id", path.stem)

    def of(self, kind: str) -> list[dict[str, Any]]:
        return [r for r in self.rows if r.get("kind") == kind]

    @property
    def source(self) -> str:
        return next((r.get("source") for r in self.rows if r.get("source")), "?")

    def counts(self) -> dict[str, Any]:
        calls = self.of("call")
        opened = next(iter(self.of("task_open")), {})
        meta = opened.get("meta") or {}
        before, after = meta.get("before", {}), meta.get("after", {})
        outside = [r for r in calls if r.get("outside_task")]
        approvals = [r for r in self.of("approval") if r.get("verb") == "ALLOW"]
        merge = next((r for r in calls if str(r.get("tool") or "").endswith("merge_pull_request") and r.get("executed")), None)
        return {
            "tool_calls": len(calls),
            "outside": len(outside),
            "outside_reached": sum(1 for r in outside if r.get("verb") != "BLOCK"),
            "outside_stopped": sum(1 for r in outside if r.get("verb") == "BLOCK"),
            "tools_before": before.get("visible_tools"), "tools_after": after.get("visible_tools"),
            "gh_before": before.get("github_tools"), "gh_after": after.get("github_tools"),
            "tok_before": before.get("approx_context_tokens"), "tok_after": after.get("approx_context_tokens"),
            "escalations": sum(1 for r in calls if r.get("verb") == "ESCALATE"),
            "approvals": approvals,
            "human_approvals": [r for r in approvals if (r.get("meta") or {}).get("human", True)],
            "merge": merge,
            "merged_by": (merge.get("approver") or "the agent itself") if merge else None,
            "main_edited": any(r.get("executed") and str(r.get("tool") or "").split(".")[-1] in WRITE_TO_MAIN
                               and str((r.get("args") or {}).get("branch") or "") in ("main", "master") for r in calls),
            "blocked_by_control": Counter(control_of(r) for r in outside if r.get("verb") == "BLOCK"),
            "by_verb": Counter(r.get("verb") for r in calls),
        }

    @property
    def is_bank(self) -> bool:
        return bool(self.header.get("caller")) or "bank" in str(self.header.get("subject") or "")

    def verdict(self, verified: str) -> tuple[str, str, str, list[str]]:
        """(word, css class, note, reasons): the same criteria as scenario.go_no_go, read from the record."""
        if self.is_bank:
            return self.bank_verdict(verified)
        c = self.counts()
        reasons = []
        merged_by, human = c["merged_by"], [a.get("approver") for a in c["human_approvals"]]
        if merged_by is None:
            reasons.append("the fix was NOT merged in this run")
        elif merged_by == "the agent itself":
            reasons.append("merged by the agent with no human approval")
        else:
            reasons.append(f"merge executed only after approval by {merged_by}" if merged_by in human else
                           f"merge auto-approved by {merged_by}: not a human; NOT go-live ready")
        if c["main_edited"]:
            reasons.append("main was edited directly by an agent")
        else:
            reasons.append("no agent wrote to main directly")
        reasons.append(f"{c['outside_reached']} of {c['outside']} out-of-task attempts reached a tool")
        reasons.append(f"signed record: {verified}")
        if "not agntid" in self.source.lower():
            reasons.append(f"enforced by {self.source}; rerun with CLEARGATE_ENFORCER=agntid for runtime evidence")
        go = (merged_by not in (None, "the agent itself") and not c["main_edited"] and c["outside_reached"] == 0
              and verified.startswith("MATCH"))
        if not go:
            return "NO-GO", "nogo", "do not promote", reasons
        if merged_by not in human:
            return "NOT GO-LIVE READY", "cond", "merge auto-approved, not a human; rerun with a named approver", reasons
        return "GO", "go", "approved by a named human", reasons

    def bank_verdict(self, verified: str) -> tuple[str, str, str, list[str]]:
        c = self.counts()
        calls = self.of("call")
        moved = [r for r in calls if r.get("executed") and "amount_inr" in (r.get("args") or {})]
        reasons = [f"money moved: " + (", ".join(f"₹{int(r['args']['amount_inr']):,} on {r['args'].get('payment_id', '?')} "
                                                f"to {str(r['args'].get('destination_account', '?'))[-4:].rjust(8, '•')}"
                                                for r in moved) or "none")]
        approved = {r.get("approver") for r in c["approvals"]}
        human = {a.get("approver") for a in c["human_approvals"]}
        if approved - human:
            reasons.append(f"approved by {', '.join(sorted(map(str, approved - human)))}: not a human")
        elif human:
            reasons.append(f"escalated refunds approved by {', '.join(sorted(map(str, human)))}")
        payee = [r for r in calls if stage_of(r).startswith("bank-system")]
        if payee:
            reasons.append(f"the bank system refused {len(payee)} call(s) at its payee check")
        reasons.append(f"{c['outside_reached']} of {c['outside']} out-of-task attempts reached a tool")
        reasons.append(f"signed record: {verified}")
        if "not agntid" in self.source.lower():
            reasons.append(f"enforced by {self.source}; rerun with CLEARGATE_ENFORCER=agntid for runtime evidence")
        if c["outside_reached"] or not verified.startswith("MATCH"):
            return "NO-GO", "nogo", "do not promote", reasons
        if approved - human:
            return "NOT GO-LIVE READY", "cond", "escalation auto-approved, not a human; rerun with a named checker", reasons
        return "GO", "go", "every call stayed inside the caller's task", reasons


def control_of(row: dict[str, Any]) -> str:
    step = row.get("denial_step") or (row.get("meta") or {}).get("denial_step") or ""
    if row.get("rule") == "visible_tools":
        step = "visible_tools"
    if row.get("intent_mismatch"):
        step = "intent"
    return CONTROL_NAMES.get(step, f"Policy rule: {row.get('rule') or step or 'default deny'}")



def pill(verb: str) -> str:
    return f'<span class="pill v-{e(verb)}">{e(verb)}</span>'


def chain_html(row: dict[str, Any]) -> str:
    parts = [e(p) for p in row.get("delegation_chain") or []]
    if row.get("tool"):
        parts.append(f"<b>{e(row['tool'])}</b>")
    return '<span class="chain">' + " &rarr; ".join(parts) + "</span>"


def ts(value: float | None, fmt: str = "%H:%M:%S") -> str:
    return time.strftime(fmt, time.localtime(value)) if value else "—"


def table(head: list[str], rows: list[list[str]], numeric: set[int] = frozenset(), row_attrs: list[str] | None = None) -> str:
    th = "".join(f'<th class="num">{h}</th>' if i in numeric else f"<th>{h}</th>" for i, h in enumerate(head))
    body = []
    for n, row in enumerate(rows):
        attrs = row_attrs[n] if row_attrs else ""
        tds = "".join(f'<td class="num">{c}</td>' if i in numeric else f"<td>{c}</td>" for i, c in enumerate(row))
        body.append(f"<tr{attrs}>{tds}</tr>")
    return f"<table><thead><tr>{th}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def refs(rows: list[dict[str, Any]], limit: int = 12) -> str:
    seqs = sorted({r["seq"] for r in rows})
    if not seqs:
        return '<span class="muted">no rows in this run</span>'
    links = ", ".join(f'<a href="#seq-{s}">#{s}</a>' for s in seqs[:limit])
    return links + (f" and {len(seqs) - limit} more" if len(seqs) > limit else "")


def section_approvals(g: RunView) -> str:
    rows = []
    for r in g.of("approval"):
        meta = r.get("meta") or {}
        call = next((c for c in g.of("call") if c.get("tool") == r.get("tool") and c["seq"] > r["seq"]
                     and c.get("args_digest") == r.get("args_digest")), None)
        human = meta.get("human", True)
        rows.append([
            f'<a href="#seq-{r["seq"]}">#{r["seq"]}</a>',
            e(r.get("approver") or "—") + ("" if human else ' <span class="pill v-ESCALATE">not a human</span>'),
            e(meta.get("via") or "?"), e(r.get("tool") or ""),
            f'<code>{e(json.dumps(r.get("args") or {}, sort_keys=True))}</code>',
            f'<code title="{e(r.get("args_digest") or "")}">{e((r.get("args_digest") or "")[:16])}…</code>'
            f' <span class="muted small">(code {e(meta.get("code") or "")})</span>',
            (f'executed at <a href="#seq-{call["seq"]}">#{call["seq"]}</a>' if call and call.get("executed") else "not executed"),
        ])
    swapped = [r for r in g.of("call") if r.get("rule") == "approval-evidence"]
    out = table(["Row", "Approver", "Via", "Tool", "Arguments approved", "Bound to digest", "Outcome"], rows) if rows \
        else '<p class="nogo box">No approval was recorded in this run.</p>'
    if swapped:
        out += ("<p><b>Approval is not a bypass.</b> After the approval, the agent retried the same tool with different "
                f"arguments; the digest no longer matched and the call was blocked ({refs(swapped)}).</p>")
    return out


def section_summary(g: RunView, s: RunView | None, attacks: dict[str, Any] | None) -> str:
    gc = g.counts()
    sc = s.counts() if s else None

    def pair(key_b: str, key_a: str, c: dict[str, Any] | None) -> str:
        return "—" if c is None else f"{c[key_b]} &rarr; {c[key_a]}"

    def val(key: str, c: dict[str, Any] | None) -> str:
        return "—" if c is None else e(str(c[key]))

    rows = [
        ["Tool calls", val("tool_calls", sc), val("tool_calls", gc)],
        ["Attempts outside the task", val("outside", sc), val("outside", gc)],
        ["&hellip; that reached a tool", val("outside_reached", sc), f"<b>{gc['outside_reached']}</b>"],
        ["&hellip; stopped", val("outside_stopped", sc), val("outside_stopped", gc)],
        ["All tools visible to the agents", pair("tools_before", "tools_after", sc), pair("tools_before", "tools_after", gc)],
        ["GitHub tools visible", pair("gh_before", "gh_after", sc), pair("gh_before", "gh_after", gc)],
        ["Tool-schema context (&asymp;tokens)", pair("tok_before", "tok_after", sc), pair("tok_before", "tok_after", gc)],
        ["Escalations to a human", val("escalations", sc), val("escalations", gc)],
        ["Merged by", e(str(sc["merged_by"])) if sc else "—", e(str(gc["merged_by"]))],
        ["Agent wrote to main directly", ("yes" if sc["main_edited"] else "no") if sc else "—", "yes" if gc["main_edited"] else "no"],
    ]
    if s:
        sw = s.verdict(load_verifier()(s.path, s.path.parent / PUBKEY)[1])[0]
        gw = g.verdict(load_verifier()(g.path, g.path.parent / PUBKEY)[1])[0]
        rows.append(["Decision", f"<b>{sw}</b>", f"<b>{gw}</b>"])
    out = table(["", f"Stock (no enforcement){'' if s else ' — not supplied'}", f"Gated ({e(g.source)})"], rows, {1, 2})
    blocked = gc["blocked_by_control"]
    if blocked:
        out += "<h3>Out-of-task attempts stopped, by control type (gated run)</h3>"
        out += table(["Control", "Stopped"], [[e(k), str(v)] for k, v in blocked.most_common()], {1})
    if attacks:
        ag = attacks.get("agntid") if isinstance(attacks.get("agntid"), dict) else {}
        res = ag.get("results") or []
        if res:
            by = Counter((r.get("expected_control"), r.get("outcome")) for r in res)
            out += "<h3>Attack suite outcomes under AgntID, by expected control</h3>"
            out += table(["Expected control", "Outcome", "Attacks"], [[e(str(k[0])), e(str(k[1])), str(v)] for k, v in sorted(by.items())], {2})
    return out


def section_delegations(g: RunView) -> str:
    rows = []
    for r in g.of("delegation"):
        meta = r.get("meta") or {}
        calls = [c for c in g.of("call") if c.get("delegation_chain") == r.get("delegation_chain")]
        rows.append([f'<a href="#seq-{r["seq"]}">#{r["seq"]}</a>', chain_html(r),
                     e(", ".join(meta.get("constraints") or []) or "none"), e(meta.get("instruction") or ""),
                     " ".join(f'{pill(v)}&nbsp;{n}' for v, n in Counter(c.get("verb") for c in calls).items()) or "—"])
    return table(["Row", "Chain", "Constraints carried", "Instruction", "Its calls"], rows)


def section_policy(g: RunView, policy_doc: dict[str, Any] | None) -> str:
    if not policy_doc:
        return f'<p class="muted">Policy file not available; version {e(g.header.get("policy_version", "?"))}.</p>'
    fired = Counter()
    for r in g.rows:
        rule = (r.get("meta") or {}).get("mirror_rule") or r.get("rule") or ""
        fired[rule.split(" ")[0]] += 1
    rows = []
    for rule in policy_doc.get("rules") or []:
        where = rule.get("where")
        scope = e(", ".join(rule.get("tools") or []))
        if where:
            scope += f'<br><span class="muted small">where {e(json.dumps(where))}</span>'
        rows.append([f'<code>{e(rule.get("id", ""))}</code>', pill(rule.get("verb", "")),
                     e(", ".join(rule.get("agents") or ["any"])), scope, e(rule.get("reason", "")),
                     str(fired.get(rule.get("id", ""), 0))])
    default = policy_doc.get("default") or {}
    rows.append(["<code>default</code>", pill(default.get("verb", "BLOCK")), "any", "anything not allowed above",
                 e(default.get("reason", "zero standing privilege")), "—"])
    vis = policy_doc.get("visible_tools") or []
    dele = policy_doc.get("delegations") or {}
    head = (f'<p><b>{e(policy_doc.get("policy", "?"))} v{e(str(policy_doc.get("version", "?")))}</b>. '
            f'First matching rule decides; anything no rule allows is blocked. '
            f'Visible once the task opens: {len(vis)} tools. Delegation constraints: '
            + e("; ".join(f"{k}: {', '.join(v) or 'none'}" for k, v in dele.items())) + ".</p>")
    return head + table(["Rule", "Verb", "Agents", "Tools / parameters", "Real-world reason", "Fired"], rows, {5})


def section_proposal(proposal: dict[str, Any] | None, name: str) -> str:
    if proposal is None:
        return ""
    out = f"<h3>Proposed policy change (<code>{e(name)}</code>, not in force for this run)</h3>"
    rules = proposal.get("rules") if isinstance(proposal, dict) else None
    if isinstance(rules, list) and rules and all(isinstance(r, dict) for r in rules):
        out += table(["Rule", "Verb", "Tools", "Reason / evidence"],
                     [[f'<code>{e(str(r.get("id", "")))}</code>', pill(str(r.get("verb", ""))),
                       e(", ".join(map(str, r.get("tools") or [r.get("tool", "")]))),
                       e(str(r.get("reason") or r.get("evidence") or ""))] for r in rules])
    else:
        out += f'<pre class="mono small">{e(json.dumps(proposal, indent=2)[:6000])}</pre>'
    return out


def section_decisions(g: RunView) -> str:
    rows, attrs = [], []
    for r in g.rows:
        meta = r.get("meta") or {}
        rule = r.get("rule") or ""
        reason = r.get("real_world_reason") or meta.get("real_world_reason") or r.get("reason") or ""
        digest = r.get("args_digest") or r.get("line_digest") or ""
        rows.append([
            f'<a id="seq-{r["seq"]}"></a>{r["seq"]}', ts(r.get("timestamp")), e(r.get("kind", "")),
            e(r.get("agent") or ""), chain_html(r), pill(r.get("verb", "")),
            f'<code>{e(rule)}</code><br><span class="small muted">{e(reason)}</span>'
            + (f'<br><span class="small">{e(r.get("reason"))}</span>' if r.get("reason") and r.get("reason") != reason else ""),
            "yes" if r.get("executed") else "no",
            decider_pill(r),
            f'<code title="{e(digest)}">{e(digest[:12])}</code>' if r.get("kind") in ("call", "approval") else "",
        ])
        attrs.append(' class="outside"' if r.get("outside_task") else "")
    return table(["#", "Time", "Kind", "Agent", "Delegation chain &rarr; tool", "Verb", "Rule / reason", "Ran",
                  "Decided by", "Digest"], rows, row_attrs=attrs)


def decider_pill(row: dict[str, Any]) -> str:
    who = decider_of(row)
    stage = stage_of(row)
    title = f"{who}: {DECIDERS[who][1]}" + (f" (stage: {stage})" if stage else "")
    return f'<span class="dec {DECIDERS[who][0]}" title="{e(title)}">{e(who)}</span>'


def section_deciders(g: RunView) -> str:
    groups: dict[str, list[dict[str, Any]]] = {k: [] for k in DECIDERS}
    for r in g.rows:
        groups[decider_of(r)].append(r)
    rows = []
    for who, rs in groups.items():
        stages = Counter(stage_of(r) for r in rs if stage_of(r))
        rows.append([f'<span class="dec {DECIDERS[who][0]}">{e(who)}</span>', str(len(rs)),
                     " ".join(f'{pill(v)}&nbsp;{n}' for v, n in Counter(r.get("verb") for r in rs).items()) or "—",
                     e(DECIDERS[who][1]) + (f'<br><span class="small muted">stages: {e(", ".join(f"{k} ({v})" for k, v in stages.items()))}</span>' if stages else ""),
                     refs(rs, 10)])
    note = ("<p class='muted small'>Read from each row's <code>stage</code>, <code>denial_step</code> and "
            "<code>source</code> fields. Only rows marked AgntID runtime are runtime evidence.</p>")
    if not groups[AGNTID]:
        note += ('<p class="box cond small">No decision in this record was made by the AgntID runtime. '
                 'Rerun with <code>CLEARGATE_ENFORCER=agntid</code> for runtime evidence.</p>')
    return note + table(["Decided by", "Rows", "Verbs", "What that means here", "Row refs"], rows, {1})


def section_attacks(attacks: dict[str, Any] | None, name: str) -> str:
    if not attacks:
        return ""
    stock = {r["id"]: r for r in attacks.get("stock") or [] if isinstance(r, dict)}
    ag = attacks.get("agntid") if isinstance(attacks.get("agntid"), dict) else {}
    agr = {r["id"]: r for r in ag.get("results") or []}
    ids = list(dict.fromkeys([*stock, *agr]))
    out = (f"<h2>9. Attack suite</h2><p><code>{e(name)}</code>: {e(str(attacks.get('summary', '')))}. "
           f"Task prompt: <i>{e(str(attacks.get('prompt', '')))}</i></p>")
    if ag.get("status") and ag.get("status") != "ready":
        out += f'<p class="box cond">AgntID runtime status: {e(ag["status"])}. {e(str(ag.get("reason", "")))}</p>'
    vis = ag.get("visible_tools") or []
    if vis and not any(not t.startswith("demo_") for t in vis):
        out += ('<p class="box cond">Caution: the runtime exposed only demo tools in this suite run, so "hidden" '
                'means the tool was absent from the runtime, not that a policy hid it.</p>')
    rows = []
    for i in ids:
        a, s = agr.get(i, {}), stock.get(i, {})
        base = a or s
        rows.append([f"<code>{e(i)}</code>", e(base.get("owasp", "")), e(base.get("klass", "")),
                     f"<code>{e(base.get('tool', ''))}</code>", e(base.get("expected_control", "")),
                     e(s.get("outcome", "not run")), e(a.get("outcome", "not run")),
                     f"<code>{e((base.get('args_digest') or '')[:12])}</code>"])
    return out + table(["Attack", "OWASP", "Class", "Tool", "Expected control", "Stock", "AgntID", "Args digest"], rows)


def section_verify(g: RunView, s: RunView | None, out_dir: Path, fingerprint: str, verified: str) -> str:
    rel = out_dir.as_posix()
    cmds = [f"cd {rel}", f"python verify.py {g.path.name}"]
    if s:
        cmds.append(f"python verify.py {s.path.name}")
    return (
        "<p>Needs only Python 3 and the <code>cryptography</code> package. No API keys, no network.</p>"
        f"<pre>{e(chr(10).join(cmds))}</pre>"
        f"<p>Expected output: <code>{e(verified)}</code></p>"
        "<p>Check the whole pack (manifest signature, every file hash, then the record):</p>"
        f"<pre>python -m cleargate.evidence verify {e(rel)}/</pre>"
        '<dl class="meta">'
        f"<dt>Public key</dt><dd><code>{PUBKEY}</code> (Ed25519)</dd>"
        f"<dt>Key fingerprint</dt><dd><code>{e(fingerprint)}</code> (SHA-256 of the raw public key)</dd>"
        f"<dt>Records</dt><dd><code>{len(g.entries)}</code> signed lines, hash-chained from a zero genesis"
        + (f", then a signed seal naming {g.seal.get('count')} records and the final hash, so truncation is detected"
           if g.seal else "; no seal line (legacy record: truncation cannot be ruled out)") + "</dd>"
        f"<dt>Final chain hash</dt><dd><code>{e(g.final_hash)}</code></dd>"
        "</dl>"
        "<p class='small muted'>The signature proves the record came from the holder of ClearGate's key; compare the "
        "fingerprint above with the one ClearGate publishes. Changing any byte of any line breaks that line's hash, its signature, and every later "
        "<code>prev_hash</code>. Write the final chain hash into the change ticket and the record cannot be swapped later.</p>"
    )


def section_standards(g: RunView, attacks: dict[str, Any] | None) -> str:
    calls = g.of("call")
    blocked_out = [r for r in calls if r.get("outside_task") and r.get("verb") == "BLOCK"]

    def reason_has(*words: str) -> list[dict[str, Any]]:
        return [r for r in g.rows if any(w.lower() in str(r.get("real_world_reason") or "").lower() for w in words)]

    atk = attacks or {}
    ag = atk.get("agntid") if isinstance(atk.get("agntid"), dict) else {}
    atk_rows = ag.get("results") or [r for r in atk.get("stock") or [] if isinstance(r, dict)]

    def atk_ref(*ids: str) -> str:
        hit = [r["id"] for r in atk_rows if r.get("owasp") in ids]
        return f"; attack suite: {len(hit)} cases ({e(', '.join(hit[:4]))}{'…' if len(hit) > 4 else ''})" if hit else ""

    narrow = g.of("task_open")
    approvals = g.of("approval") + [r for r in calls if r.get("verb") == "ESCALATE"]
    swapped = [r for r in calls if r.get("rule") == "approval-evidence"]
    deleg = g.of("delegation") + [r for r in calls if (r.get("denial_step") == "delegation")]
    closed = g.of("task_close") + [r for r in calls if r.get("denial_step") == "task_resolution"]
    c = g.counts()
    human = [a.get("approver") for a in c["human_approvals"]]
    if c["merged_by"] is None:
        oversight = "The fix was not merged in this run, so no merge approval is shown."
    elif c["merged_by"] in human:
        oversight = (f"{e(c['merged_by'])} approved the state-changing merge after seeing its arguments; the approval "
                     "binds to the exact arguments digest and the system stops on mismatch.")
    elif c["merged_by"] == "the agent itself":
        oversight = "The merge ran with no approval at all. No human oversight is shown by this run."
    else:
        oversight = (f"In this run the merge was auto-approved ({e(c['merged_by'])}): not a human, so this run is "
                     "NOT go-live ready. The approval still binds to the arguments digest and a swapped target is blocked; "
                     "a go-live run needs a named engineer to approve.")
    injected = (f"{c['outside_stopped']} of {c['outside']} out-of-task calls were stopped before the tool ran"
                + ("." if c["outside_reached"] == 0 else f"; {c['outside_reached']} reached a tool."))
    items = [
        ("OWASP Agentic Top 10 — ASI01 / ASI06 goal hijack, context poisoning",
         "The issue body carries an injected instruction. " + injected,
         refs(blocked_out) + atk_ref("ASI01", "ASI06")),
        ("OWASP Agentic Top 10 — ASI02 tool misuse",
         "Tools are narrowed when the task opens; out-of-scope tools and parameters are denied per call.",
         refs(narrow + [r for r in blocked_out if r.get("rule") in ("visible_tools",) or r.get("denial_step") == "policy_evaluation"]) + atk_ref("ASI02")),
        ("OWASP Agentic Top 10 — ASI03 identity and privilege abuse",
         "Each sub-agent acts under its own delegation with constraints carried down (read-only triage and database).",
         refs(deleg) + atk_ref("ASI03")),
        ("OWASP Agentic Top 10 — ASI09 human-agent trust exploitation",
         oversight,
         refs(approvals + swapped) + atk_ref("ASI09")),
        ("EU AI Act Art. 12 — record-keeping",
         "Every decision, including denials, is logged automatically to a signed, hash-chained record with time, actor, tool, rule and arguments digest.",
         f"all {len(g.rows)} rows; final chain hash <code>{e(g.final_hash[:16])}…</code>"),
        ("EU AI Act Art. 14 — human oversight",
         oversight,
         refs(approvals + swapped)),
        ("RBI FREE-AI — audit and assurance (\"record the whole journey\")",
         "The full delegation journey user &rarr; orchestrator &rarr; sub-agent &rarr; tool is recorded per call and verifiable offline by the bank; the trust anchor is ClearGate's published key fingerprint "
         f"(<code>{e(g.header.get('pubkey_sha256', '')[:16])}…</code>).",
         refs(g.of("delegation")) + "; verify box above"),
        ("DPDP Act — purpose limitation and data minimisation",
         "Access is scoped to this task's purpose: bulk export and external email are blocked, refund reads are bounded, and access ends when the task closes.",
         refs(narrow + reason_has("DPDP") + closed)),
        ("PCI DSS v4 Req. 7 — restrict access by business need to know",
         "Card-holder data tools are not visible to the incident task and bulk export is denied; least privilege is per call.",
         refs(narrow + reason_has("PCI", "least privilege"))),
    ]
    return table(["Framework / control (evidence for, not a compliance claim)", "What this run shows", "Evidence rows"],
                 [[f"<b>{t}</b>", d, ref] for t, d, ref in items])


REPORT_SECTIONS = {"did": "What the agents did", "decided": "What was decided", "risks": "Risks"}


def clip(text: str, limit: int = 110) -> str:
    """A verbatim prefix of a record string, cut at a word boundary, safe to put in double quotes."""
    text = " ".join(str(text).split()).split('"', 1)[0]
    if len(text) <= limit:
        return text.rstrip(" .;:,")
    return text[:limit].rsplit(" ", 1)[0].rstrip(" .;:,(")


def short(tool: Any) -> str:
    return str(tool or "").rsplit(".", 1)[-1]


def decider_facts(g: RunView, facts: RecordFacts) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {k: [] for k in DECIDERS}
    for r in g.rows:
        groups[decider_of(r)].append(r)
    words = {AGNTID: ["agntid", "runtime"], STAND_IN: ["stand-in", "local", "simulat"], APP: ["cleargate", "app"],
             BANK: ["bank"]}
    for who, rs in groups.items():
        facts.extra_name(who, [r["seq"] for r in rs])
        facts.extra(len(rs), f"rows decided by the {who}", words[who] + ["decided", "decision", "row"], [r["seq"] for r in rs])
    simulated = [r for r in g.rows if stage_of(r).startswith("local-simulation")]
    facts.extra(len(simulated), "rows that simulate an AgntID control locally", ["simulat", "local"], [r["seq"] for r in simulated])
    return groups


def draft_template(g: RunView, verdict: str, groups: dict[str, list[dict[str, Any]]]) -> dict[str, list[str]]:
    c = g.counts()
    calls = g.of("call")
    agents = list(dict.fromkeys(r.get("agent") for r in g.of("delegation") if r.get("agent") != "orchestrator"))
    did, decided, risks = [], [], []
    opened = next(iter(g.of("task_open")), {})
    prompt = (opened.get("meta") or {}).get("prompt")
    if g.is_bank and prompt:
        did.append(f'The caller said: "{clip(prompt, 160)}".')
    if agents:
        did.append(f"{len(agents)} agents worked under {len(g.of('delegation'))} delegations: "
                   + ", ".join(f"`{a}`" for a in agents) + ".")
    did.append(f"They made {c['tool_calls']} tool calls and {sum(1 for r in calls if r.get('executed'))} of them ran.")
    if c["tools_before"] is not None and c["tools_after"] is not None:
        did.append(f"When the task opened, the visible tools went from {c['tools_before']} to {c['tools_after']}.")
    for r in calls:
        if r.get("executed") and not short(r.get("tool")).startswith(READ_PREFIXES):
            amount = (r.get("args") or {}).get("amount_inr")
            did.append(f"`{r['tool']}` ran at #{r['seq']}" + (f" for ₹{int(amount):,}" if isinstance(amount, (int, float)) else "") + ".")
    if c["outside"]:
        decided.append(f"{c['outside_stopped']} of {c['outside']} out-of-task "
                       f"{'attempt was' if c['outside'] == 1 else 'attempts were'} stopped before the tool ran.")
    seen: set[str] = set()
    for r in calls:
        rule = str(r.get("rule") or "").split(" (", 1)[0]
        if r.get("verb") != "BLOCK" or rule in seen or len(seen) >= 4:
            continue
        seen.add(rule)
        decided.append(f'`{rule}` blocked `{r["tool"]}` at #{r["seq"]}: "{clip(r.get("reason"))}".')
    for r in g.of("approval"):
        decided.append(f'`{r["tool"]}` was escalated and approved by "{r.get("approver")}" at #{r["seq"]}.'
                       if r.get("verb") == "ALLOW" else f'`{r["tool"]}` was escalated and rejected at #{r["seq"]}.')
    for who, rs in groups.items():
        if rs:
            decided.append(f"{len(rs)} of {len(g.rows)} decision rows were decided by the {who}.")
    decided.append(f"The verdict computed from the record is {verdict}.")
    if "not agntid" in g.source.lower():
        risks.append(f'Every row names "{g.source}" as its enforcement source, so this record is not AgntID runtime evidence.')
    simulated = [r for r in g.rows if stage_of(r).startswith("local-simulation")]
    if simulated:
        risks.append(f"{len(simulated)} {'row is a local simulation' if len(simulated) == 1 else 'rows are local simulations'} "
                     f"of AgntID controls, such as `{stage_of(simulated[0])}`.")
    for a in c["approvals"]:
        if not (a.get("meta") or {}).get("human", True):
            risks.append(f'The approval at #{a["seq"]} came from "{a.get("approver")}", which is not a named human.')
    if c["outside_reached"]:
        risks.append(f"{c['outside_reached']} out-of-task attempts reached a tool.")
    for r in calls:
        if r.get("rule") == "approval-evidence":
            risks.append(f'A call that reused the approval with other arguments was blocked by `approval-evidence` at #{r["seq"]}.')
    payee = [r for r in calls if stage_of(r).startswith("bank-system")]
    if payee:
        risks.append(f"The bank system refused {len(payee)} calls at `bank-system-payee-check`; the agent did not stop them itself.")
    if not risks:
        risks.append(f"{c['outside_reached']} of {c['outside']} out-of-task attempts reached a tool.")
    return {"did": did, "decided": decided, "risks": risks}


LLM_SYSTEM = """You write the go-live report for an audit evidence pack about an AI agent run. You get a JSON digest of a
signed decision record. Write three short sections: what the agents did, what was decided, and the risks.

Hard rules, because code checks every sentence against the record and deletes any it cannot confirm:
- One claim per sentence, 2 to 4 sentences per section, plain language, no adjectives.
- Every sentence must contain at least one number from the digest, a "double-quoted" exact substring of a record
  string (reason, rule, transcript), or a tool/rule/agent name in `backticks`.
- Numbers: use digits, only counts and amounts that appear in the digest's `counts` or the rows; say what was counted
  right next to the number ("9 tool calls", "2 blocked"). No times, dates, percentages or row totals you computed.
- Quotes must be copied character for character. Put every tool, rule and agent name in backticks.
- Cite rows as #<seq> when you talk about one decision.
- If you state the go-live verdict, use the digest's verdict word exactly.
Return only JSON: {"did": [...], "decided": [...], "risks": [...]}"""


def llm_digest(g: RunView, verdict: str, reasons: list[str], groups: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    c = g.counts()
    rows = []
    for r in g.rows:
        row = {"seq": r["seq"], "kind": r.get("kind"), "agent": r.get("agent"), "tool": r.get("tool"), "verb": r.get("verb"),
               "rule": r.get("rule"), "reason": r.get("reason"), "executed": r.get("executed"),
               "outside_task": r.get("outside_task"), "approver": r.get("approver"), "decided_by": decider_of(r),
               "stage": stage_of(r) or None,
               "args": {k: v for k, v in (r.get("args") or {}).items() if isinstance(v, (int, float, str)) and len(str(v)) < 40}}
        rows.append({k: v for k, v in row.items() if v not in (None, "", False, {})})
    counts = {k: c[k] for k in ("tool_calls", "outside", "outside_reached", "outside_stopped", "tools_before",
                                "tools_after", "escalations")}
    counts["executed"] = sum(1 for r in g.of("call") if r.get("executed"))
    counts["blocked"] = c["by_verb"].get("BLOCK", 0)
    counts["delegations"] = len(g.of("delegation"))
    counts["decided_by"] = {k: len(v) for k, v in groups.items()}
    opened = next(iter(g.of("task_open")), {})
    return {"subject": g.header.get("subject") or "payments incident agent team",
            "task_prompt_or_transcript": (opened.get("meta") or {}).get("prompt"), "enforced_by": g.source,
            "verdict": verdict, "verdict_reasons": reasons, "counts": counts, "rows": rows}


def draft_llm(g: RunView, verdict: str, reasons: list[str], groups: dict[str, list[dict[str, Any]]]) -> tuple[dict[str, list[str]], str] | None:
    settings = Settings()
    if settings.llm in ("", "scripted"):
        return None
    from cleargate.agents.team import make_brain

    brain = make_brain(settings)
    if not hasattr(brain, "client") and not hasattr(brain, "anthropic_api_key"):
        return None
    messages = [{"role": "system", "content": LLM_SYSTEM},
                {"role": "user", "content": json.dumps(llm_digest(g, verdict, reasons, groups), ensure_ascii=False)}]
    try:
        turn = brain.next_turn("reporter", messages, [])
    except Exception as exc:  # the template takes over; the pack still builds offline
        print(f"go-live report: LLM unavailable ({str(exc)[:160]}); using the template", file=sys.stderr)
        return None
    text = turn.content.strip()
    text = text[text.find("{"):text.rfind("}") + 1] if "{" in text else ""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        print("go-live report: the LLM did not return JSON; using the template", file=sys.stderr)
        return None
    draft = {k: [str(x) for x in doc.get(k) or [] if str(x).strip()] for k in REPORT_SECTIONS}
    return (draft, brain.label) if any(draft.values()) else None


def cite_html(claim: Claim, limit: int = 4) -> str:
    by_seq: dict[int, list[str]] = {}
    hashes: dict[int, str] = {}
    for s in claim.supports:
        by_seq.setdefault(s.seq, []).append(s.note)
        hashes[s.seq] = s.hash
    out = []
    for seq, notes in list(by_seq.items())[:limit]:
        target, label = (f"#seq-{seq}", f"#{seq}") if seq else ("#verify", "header")
        title = f"record line seq {seq}, line hash {hashes[seq]}\n" + "\n".join(dict.fromkeys(notes))
        out.append(f'<a class="cite" href="{target}" title="{e(title)}">{label}</a>')
    more = len(by_seq) - limit
    return " ".join(out) + (f' <span class="muted small">+{more}</span>' if more > 0 else "")


def claim_html(text: str) -> str:
    parts = text.split("`")
    return "".join(f"<code>{e(p)}</code>" if i % 2 else e(p) for i, p in enumerate(parts))


INJECTED = ' <span class="pill v-ESCALATE">injected</span>'


def section_report(claims: list[Claim], drafted_by: str, injected: set[str]) -> str:
    kept = [c for c in claims if c.kept]
    removed = [c for c in claims if not c.kept]
    out = (f'<p class="muted small">Drafted by {e(drafted_by)}. Code checked every sentence against the signed record: '
           "numbers against counts and amounts computed from it, quotes word for word, names against the tools, rules "
           f"and agents it contains. <b>{len(kept)} of {len(claims)} claims kept.</b> Hover a citation for the record "
           "line and its hash; click to jump to the row.</p>")
    for key, title in REPORT_SECTIONS.items():
        mine = [c for c in kept if c.section == key]
        if mine:
            out += f"<h3>{title}</h3><ul class='claims'>" + "".join(
                f"<li>{claim_html(c.text)} <span class='cites'>{cite_html(c)}</span></li>" for c in mine) + "</ul>"
    if removed:
        out += ('<div class="box removed"><div class="removed-head">Removed: not supported by the record</div><ul>'
                + "".join(f"<li><s>{claim_html(c.text)}</s>{INJECTED if c.text in injected else ''}"
                          f"<br><span class='small'>{e(c.reason)}</span></li>" for c in removed) + "</ul></div>")
    return out


def load_draft(path: Path) -> tuple[dict[str, list[str]], str]:
    """A saved draft: {"did": [...], ...} or a previous pack's report.json (its injected sentences left out)."""
    doc = json.loads(path.read_text())
    if "claims" in doc:
        injected = set(doc.get("injected") or [])
        draft: dict[str, list[str]] = {k: [] for k in REPORT_SECTIONS}
        for c in doc["claims"]:
            if c["text"] not in injected:
                draft.setdefault(c["section"], []).append(c["text"])
        origin = str(doc.get("drafted_by", "a saved draft")).split(" (saved draft ", 1)[0]
        return draft, f"{origin} (saved draft {path.name}, re-checked)"
    return {k: [str(x) for x in doc.get(k) or []] for k in REPORT_SECTIONS}, f"a saved draft ({path.name})"


def go_live_report(g: RunView, verdict: str, reasons: list[str], policy_doc: dict[str, Any] | None,
                   inject: list[str], saved: Path | None = None) -> tuple[str, dict[str, Any]]:
    facts = RecordFacts(g.entries, verdict, policy_doc, reasons)
    groups = decider_facts(g, facts)
    llm = load_draft(saved) if saved else draft_llm(g, verdict, reasons, groups)
    draft, drafted_by = llm if llm else (draft_template(g, verdict, groups), "the deterministic template (no LLM configured)")
    if inject:
        draft["decided"] = draft.get("decided", []) + list(inject)
    claims = check_draft(draft, facts)
    report = {"drafted_by": drafted_by, "kept": sum(c.kept for c in claims), "removed": sum(not c.kept for c in claims),
              "injected": list(inject), "claims": [c.as_dict() for c in claims]}
    return section_report(claims, drafted_by, set(inject)), report


def sign_manifest(manifest: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    body = {k: v for k, v in manifest.items() if k != "signature"}
    sig = base64.b64encode(key.sign(canonical_json(body).encode("utf-8"))).decode("ascii")
    return body | {"signature": sig}


def load_signing_key(settings: Settings, expected_fp: str) -> Ed25519PrivateKey:
    if not (settings.state_dir / "signing_key.pem").exists():
        raise SystemExit(f"no signing key at {settings.state_dir / 'signing_key.pem'}; the pack must be signed by the record's key")
    key = load_or_create_key(settings.state_dir, settings.records_dir)
    if public_key_fingerprint(key) != expected_fp:
        raise SystemExit("the local signing key is not the key that signed this record; refusing to sign the pack")
    return key


def build(record: Path, stock: Path | None, attacks: Path | None, proposal: Path | None, out: Path | None,
          inject: list[str] | None = None, saved_draft: Path | None = None) -> Path:
    settings = Settings()
    verify = load_verifier()
    g = RunView(record)
    pub_src = record.parent / PUBKEY
    if stock is None:
        guess = record.with_name(record.name.replace("-gated.jsonl", "-stock.jsonl"))
        stock = guess if guess != record and guess.exists() else None
    s = RunView(stock) if stock else None
    out = out or ROOT / "evidence" / g.run_id
    out.mkdir(parents=True, exist_ok=True)
    key = load_signing_key(settings, g.header.get("pubkey_sha256", ""))
    fingerprint = public_key_fingerprint(key)

    included: list[tuple[str, str]] = []

    def copy(src: Path, name: str, role: str) -> Path:
        dst = out / name
        if src.resolve() != dst.resolve():
            shutil.copyfile(src, dst)
        included.append((name, role))
        return dst

    g.path = copy(record, record.name, "signed record (gated)")
    if s:
        s.path = copy(stock, stock.name, "signed record (stock)")
    copy(pub_src, PUBKEY, "Ed25519 public key")
    copy(ROOT / "verify.py", "verify.py", "offline verifier")
    policy_doc = None
    policy_path = Path(g.header.get("policy_path") or "")
    if policy_path.is_file():
        policy_doc = yaml.safe_load(policy_path.read_text()) or {}
        copy(policy_path, "policy.yaml", "policy in force (" + g.header.get("policy_version", "?") + ")")
    attacks_doc = proposal_doc = None
    if attacks:
        attacks_doc = json.loads(attacks.read_text())
        copy(attacks, "attacks.json", "attack suite results")
    if proposal:
        proposal_doc = json.loads(proposal.read_text())
        copy(proposal, "policy-proposal.json", "proposed policy (not in force)")

    ok, verified = verify(g.path, out / PUBKEY)
    word, klass, note, reasons = g.verdict(verified)
    report_html, report = go_live_report(g, word, reasons, policy_doc, inject or [], saved_draft)
    (out / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    included.append(("report.json", "go-live report claims, kept and removed, with the record lines they rest on"))
    opened = next(iter(g.of("task_open")), {})
    try:
        rel_out = out.resolve().relative_to(ROOT)
    except ValueError:
        rel_out = out.resolve()
    css = (TEMPLATES / "style.css").read_text()
    page = string.Template((TEMPLATES / "index.html").read_text()).substitute(
        css=css, run_id=e(g.run_id),
        title=e("bank voice support agent" if g.is_bank else "payments incident agent team"),
        report=report_html, deciders=section_deciders(g), recorded=e(ts(g.header.get("created"), "%Y-%m-%d %H:%M:%S %Z")),
        task_prompt=e((opened.get("meta") or {}).get("prompt", "")),
        policy_version=e(g.header.get("policy_version", "?")), source=e(g.source),
        backends=e("; ".join(f"{k}: {v}" for k, v in (g.header.get("tools") or {}).items())),
        generated=e(time.strftime("%Y-%m-%d %H:%M:%S %Z")),
        verdict_class=klass, verdict_word=word, verdict_note=e(note),
        reasons='<ul class="reasons">' + "".join(f"<li>{e(r)}</li>" for r in reasons) + "</ul>",
        approvals=section_approvals(g), summary=section_summary(g, s, attacks_doc),
        delegations=section_delegations(g), policy=section_policy(g, policy_doc),
        proposal=section_proposal(proposal_doc, proposal.name if proposal else ""),
        decisions=section_decisions(g), attacks=section_attacks(attacks_doc, attacks.name if attacks else ""),
        verify=section_verify(g, s, Path(str(rel_out)), fingerprint, verified),
        standards=section_standards(g, attacks_doc),
    )
    (out / "index.html").write_text(page, encoding="utf-8")
    included.insert(0, ("index.html", "go-live decision (human-readable)"))

    manifest = {
        "kind": "cleargate-evidence-pack", "version": 1, "run_id": g.run_id,
        "generated": time.time(), "verdict": word, "reasons": reasons,
        "report": {k: report[k] for k in ("drafted_by", "kept", "removed")},
        "pubkey_sha256": fingerprint, "policy_version": g.header.get("policy_version"),
        "records": {v.mode: {"file": v.path.name, "lines": len(v.entries), "final_hash": v.final_hash}
                    for v in (g, s) if v},
        "files": [{"path": n, "role": r, "bytes": (out / n).stat().st_size, "sha256": sha256_file(out / n)}
                  for n, r in included],
        "verify": [
            "python -m cleargate.evidence verify <this folder>",
            f"or by hand: python verify.py {g.path.name}  (inside this folder)",
            "manifest signature: Ed25519 by signing_pub.pem over the canonical JSON (sorted keys, no spaces, UTF-8) "
            "of this object without the 'signature' field",
        ],
    }
    (out / MANIFEST).write_text(json.dumps(sign_manifest(manifest, key), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def verify_pack(folder: Path) -> tuple[bool, list[str]]:
    lines: list[str] = []
    try:
        manifest = json.loads((folder / MANIFEST).read_text())
        pub = serialization.load_pem_public_key((folder / PUBKEY).read_bytes())
    except (OSError, ValueError) as exc:
        return False, [f"MISMATCH: cannot read the manifest or public key ({exc})"]
    if not isinstance(pub, Ed25519PublicKey):
        return False, ["MISMATCH: signing_pub.pem is not an Ed25519 key"]
    fp = hashlib.sha256(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
    if fp != manifest.get("pubkey_sha256"):
        return False, ["MISMATCH: the manifest names a different public key than signing_pub.pem"]
    body = {k: v for k, v in manifest.items() if k != "signature"}
    try:
        pub.verify(base64.b64decode(manifest.get("signature", "")), canonical_json(body).encode("utf-8"))
    except (InvalidSignature, ValueError):
        return False, ["MISMATCH: manifest signature is invalid"]
    lines.append(f"manifest signature valid (key {fp[:16]}…)")
    ok = True
    listed = {f["path"] for f in manifest.get("files", [])}
    for f in manifest.get("files", []):
        p = folder / f["path"]
        if not p.is_file():
            ok = False
            lines.append(f"MISMATCH: {f['path']} is missing")
        elif sha256_file(p) != f["sha256"]:
            ok = False
            lines.append(f"MISMATCH: {f['path']} sha256 differs from the manifest")
    if ok:
        lines.append(f"{len(listed)} files match their sha256")
    extra = sorted(p.name for p in folder.iterdir() if p.is_file() and p.name not in listed | {MANIFEST})
    if extra:
        lines.append(f"note: files not covered by the manifest: {', '.join(extra)}")
    verify = load_verifier()
    for mode, rec in (manifest.get("records") or {}).items():
        good, message = verify(folder / rec["file"], folder / PUBKEY)
        last = read_record(folder / rec["file"])[-1]["hash"] if good else ""
        if good and last != rec.get("final_hash"):
            good, message = False, "MISMATCH: final chain hash differs from the manifest"
        ok &= good
        lines.append(f"{mode} record {rec['file']}: {message}")
    lines.append(("MATCH: evidence pack intact. Verdict on file: " + str(manifest.get("verdict"))) if ok
                 else "MISMATCH: evidence pack failed verification")
    return ok, lines


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "verify":
        p = argparse.ArgumentParser(prog="python -m cleargate.evidence verify")
        p.add_argument("folder", type=Path)
        a = p.parse_args(argv[1:])
        ok, lines = verify_pack(a.folder)
        print("\n".join(lines))
        return 0 if ok else 1
    p = argparse.ArgumentParser(prog="python -m cleargate.evidence", description=__doc__.splitlines()[0])
    p.add_argument("--record", type=Path, required=True, help="signed gated record (*-gated.jsonl)")
    p.add_argument("--stock", type=Path, help="signed stock record (default: the sibling *-stock.jsonl if present)")
    p.add_argument("--attacks", type=Path, help="attack-suite results JSON (records/attacks-*.json)")
    p.add_argument("--policy", type=Path, help="proposed policy JSON to attach (not in force)")
    p.add_argument("--out", type=Path, help="output folder (default evidence/<run_id>/)")
    p.add_argument("--inject-claim", action="append", default=[], metavar="SENTENCE",
                   help="add a sentence to the go-live report draft (shows the claim checker dropping it)")
    p.add_argument("--draft", type=Path, help="re-check a saved draft (JSON or a previous report.json) instead of drafting")
    a = p.parse_args(argv)
    out = build(a.record, a.stock, a.attacks, a.policy, a.out, a.inject_claim, a.draft)
    ok, lines = verify_pack(out)
    manifest = json.loads((out / MANIFEST).read_text())
    print(f"Evidence pack: {out}/index.html")
    print(f"Verdict: {manifest['verdict']}")
    rep = manifest.get("report") or {}
    print(f"Go-live report: {rep.get('kept')} claims kept, {rep.get('removed')} removed (drafted by {rep.get('drafted_by')})")
    print(lines[-1])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

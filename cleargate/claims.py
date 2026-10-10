"""Claim checker for the go-live report: the model explains, code proves.

A draft (from an LLM or the deterministic template) is split into claims. A claim survives only if
  - every number in it equals a count or amount computed from the signed record, and the words around
    the number name what was counted (so a true number attached to the wrong thing is still dropped),
  - every "quoted" string appears verbatim in the record (decision reasons, rules, transcript lines),
  - every `backticked`, dotted or snake_case name is a tool, rule, agent or step that exists in the record,
  - any go-live verdict it states is the verdict computed from the record,
  - and it rests on at least one of the above. A sentence the record cannot confirm is not kept.
Each surviving claim carries the record lines (seq + line hash) it rests on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

WINDOW = 7
NUMBER_WORDS = {w: n for n, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen "
    "seventeen eighteen nineteen twenty".split()) if w != "one"}
VERDICTS = ("NOT GO-LIVE READY", "NO-GO", "GO")
STOP = set("the and for with from that this was were are has have had into only over under not any all its "
           "their them they then than been being when where which while what who whom".split())

QUOTE_RE = re.compile(r'"([^"\n]{2,}?)"|“([^”\n]{2,}?)”')
TICK_RE = re.compile(r"`([^`\n]+)`")
NAME_RE = re.compile(r"(?<![\w`])([A-Za-z][\w-]*(?:\.[A-Za-z_][\w-]*)+|[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+)(?![\w`])")
HEX_RE = re.compile(r"^[0-9a-f]{8,64}$")
NUM_RE = re.compile(r"(?<![\w.#/-])(₹\s?|INR\s?|Rs\.?\s?)?(\d{1,3}(?:,\d{2,3})+|\d+(?:\.\d+)?)(%)?(?![\w/-]|\.\d)")
SEQ_RE = re.compile(r"(?:#|\brows?\s+#?)(\d+)\b", re.I)
WORD_RE = re.compile(r"[\w₹#%.-]+")
NOT_NAMES = {"e.g", "i.e", "etc", "vs"}
ALL_AGENTS = frozenset({"*agents"})
DONE_WORDS = set("ran executed refunded refund refunds merged moved paid transferred credited succeeded completed posted "
                 "created opened sent wrote issued".split())
BLOCK_WORDS = set("blocked denied refused stopped rejected prevented hidden failed attempted tried".split())


@dataclass(frozen=True)
class Support:
    seq: int
    hash: str
    note: str


@dataclass
class Fact:
    value: Decimal
    label: str
    keywords: tuple[str, ...]
    seqs: tuple[int, ...] = ()
    scope: frozenset[str] = frozenset()
    stated: bool = False


@dataclass
class Claim:
    text: str
    section: str
    supports: list[Support] = field(default_factory=list)
    reason: str = ""

    @property
    def kept(self) -> bool:
        return not self.reason

    def as_dict(self) -> dict[str, Any]:
        return {"section": self.section, "text": self.text, "kept": self.kept, "reason": self.reason,
                "supports": [{"seq": s.seq, "hash": s.hash, "note": s.note} for s in self.supports]}


def to_decimal(text: str) -> Decimal | None:
    try:
        return Decimal(text.replace(",", ""))
    except InvalidOperation:
        return None


def norm(text: str) -> str:
    text = text.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"').replace("…", "...")
    return re.sub(r"\s+", " ", text).strip()


def content_words(text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(w for w in re.findall(r"[a-z][a-z-]{3,}", text.lower()) if w not in STOP))


class RecordFacts:
    """Everything a claim may rest on, computed from the record lines."""

    def __init__(self, entries: list[dict[str, Any]], verdict: str = "", policy_doc: dict[str, Any] | None = None,
                 verdict_reasons: list[str] | None = None):
        self.entries = entries
        self.verdict_reasons = verdict_reasons or []
        self.hash_of = {en["seq"]: en.get("hash", "") for en in entries}
        self.final_hash = entries[-1].get("hash", "") if entries else ""
        self.verdict = verdict
        self.header = entries[0]["payload"] if entries else {}
        self.rows = [dict(en["payload"], seq=en["seq"]) for en in entries[1:]]
        self.facts: list[Fact] = []
        self.names: dict[str, set[int]] = {}
        self.primary: dict[str, set[int]] = {}
        self.row_terms: dict[int, set[str]] = {}
        self.corpus: list[tuple[int, str, str]] = []
        self._index_names(policy_doc or {})
        self._index_corpus()
        self._index_numbers()

    def add(self, value: Any, label: str, keywords: tuple[str, ...] | list[str], rows: Any = (),
            scope: set[str] | frozenset[str] = frozenset(), stated: bool = False) -> None:
        if value is None or isinstance(value, bool):
            return
        number = to_decimal(str(value))
        if number is None:
            return
        seqs = tuple(sorted({r["seq"] if isinstance(r, dict) else int(r) for r in rows}))
        self.facts.append(Fact(number, label, tuple(k.lower() for k in keywords), seqs, frozenset(scope), stated))

    def _name(self, name: Any, seq: int) -> None:
        if not name:
            return
        name = str(name).strip()
        self.names.setdefault(name, set()).add(seq)
        if "." in name and not name.startswith("."):
            self.names.setdefault(name.rsplit(".", 1)[-1], set()).add(seq)
        if " (" in name:
            self._name(name.split(" (", 1)[0], seq)

    def _index_names(self, policy_doc: dict[str, Any]) -> None:
        for key in ("run_id", "policy_version", "policy", "mode"):
            self._name(self.header.get(key), 0)
        for r in self.rows:
            meta = r.get("meta") or {}
            for value in (r.get("tool"), r.get("rule"), r.get("policy_name"), r.get("agent"), r.get("denial_step"),
                          r.get("kind"), r.get("verb"), meta.get("mirror_rule"), meta.get("stage"), r.get("stage")):
                self._name(value, r["seq"])
                if value:
                    terms = {str(value), str(value).rsplit(".", 1)[-1], str(value).split(" (", 1)[0]}
                    self.row_terms.setdefault(r["seq"], set()).update(terms)
                    for t in terms:
                        self.primary.setdefault(t, set()).add(r["seq"])
            for part in r.get("delegation_chain") or []:
                self._name(part, r["seq"])
            for tool in (meta.get("visible") or []) + (meta.get("relevant_tool_names") or []) + (meta.get("tool_allowlist") or []):
                self._name(tool, r["seq"])
            for c in meta.get("constraints") or []:
                self._name(c, r["seq"])
            for key, value in (r.get("args") or {}).items():
                self._name(key, r["seq"])
                if isinstance(value, str) and re.fullmatch(r"[\w.-]+", value):
                    self._name(value, r["seq"])
        for rule in policy_doc.get("rules") or []:
            self._name(rule.get("id"), 0)
            for tool in rule.get("tools") or []:
                self._name(tool, 0)

    def _index_corpus(self) -> None:
        for key in ("subject", "intent", "caller", "policy_path"):
            if self.header.get(key):
                self.corpus.append((0, f"header {key}", norm(str(self.header[key]))))
        last = self.entries[-1]["seq"] if self.entries else 0
        for reason in self.verdict_reasons:
            self.corpus.append((last, "verdict reasons computed from the whole record", norm(reason)))
        for r in self.rows:
            meta = r.get("meta") or {}
            fields = {"reason": r.get("reason"), "real-world reason": r.get("real_world_reason") or meta.get("real_world_reason"),
                      "rule": r.get("rule"), "intent mismatch": r.get("intent_mismatch"), "result": r.get("result_preview"),
                      "approver": r.get("approver"), "instruction": meta.get("instruction"), "note": meta.get("note"),
                      "transcript" if self.header.get("caller") else "task prompt": meta.get("prompt"),
                      "source": r.get("source")}
            for label, text in fields.items():
                if text:
                    self.corpus.append((r["seq"], label, norm(str(text))))

    def _index_numbers(self) -> None:
        rows, calls = self.rows, [r for r in self.rows if r.get("kind") == "call"]
        outside = [r for r in calls if r.get("outside_task")]
        verb = lambda v, rs=calls: [r for r in rs if r.get("verb") == v]
        executed = [r for r in calls if r.get("executed")]
        approvals = [r for r in rows if r.get("kind") == "approval"]
        human = [r for r in approvals if r.get("verb") == "ALLOW" and (r.get("meta") or {}).get("human", True)]
        delegations = [r for r in rows if r.get("kind") == "delegation"]
        agents = {r.get("agent") for r in rows if r.get("agent") and r.get("agent") != "orchestrator"}
        self.add(len(self.entries), "signed lines in the record", ["line", "record", "signed", "entries"], [0])
        self.add(len(rows), "decision rows after the header", ["row", "decision", "record", "entries", "event"], rows)
        self.add(len(calls), "tool calls", ["call", "attempt", "request"], calls)
        self.add(len(executed), "tool calls that ran", ["ran", "run", "executed", "succeeded", "went through", "completed"], executed)
        self.add(len(verb("ALLOW")), "calls allowed", ["allow", "permitted", "approved", "went through"], verb("ALLOW"))
        self.add(len(verb("BLOCK")), "calls blocked", ["block", "denied", "stopped", "refused", "rejected"], verb("BLOCK"))
        self.add(len(verb("ESCALATE")), "calls escalated to a human", ["escalat", "review", "approval", "human", "sent to"], verb("ESCALATE"))
        self.add(len(outside), "out-of-task attempts", ["outside", "out-of-task", "out of task", "out-of-scope",
                                                         "attempt", "injected", "off-task"], outside)
        self.add(sum(1 for r in outside if r.get("verb") != "BLOCK"), "out-of-task attempts that reached a tool",
                 ["reached", "got through", "slipped", "executed", "ran"], [r for r in outside if r.get("verb") != "BLOCK"])
        self.add(sum(1 for r in outside if r.get("verb") == "BLOCK"), "out-of-task attempts stopped",
                 ["stopped", "blocked", "denied", "refused", "caught"], [r for r in outside if r.get("verb") == "BLOCK"])
        self.add(len(approvals), "approval decisions", ["approv", "sign-off", "signed off"], approvals)
        self.add(len(human), "approvals by a human", ["human", "engineer", "person", "approv"], human)
        self.agents = {str(r.get("agent")) for r in rows if r.get("agent")}
        self.tools = {t for r in calls for t in (str(r.get("tool")), str(r.get("tool")).rsplit(".", 1)[-1])}
        self.add(len(delegations), "delegations", ["delegat", "hand-off", "handoff", "sub-agent", "agent"], delegations, ALL_AGENTS)
        self.add(len(agents), "distinct agents (excluding the orchestrator)", ["agent", "sub-agent", "worker"], delegations, ALL_AGENTS)
        for r in rows:
            if r.get("kind") != "task_open":
                continue
            meta = r.get("meta") or {}
            before, after = meta.get("before") or {}, meta.get("after") or {}
            for key, label, kws in (("visible_tools", "tools", ["visible", "narrow", "tools visible", "available", "exposed"]),
                                    ("github_tools", "GitHub tools", ["github"]),
                                    ("approx_context_tokens", "tool-schema tokens", ["token", "context", "schema"])):
                b, a = before.get(key), after.get(key)
                self.add(b, f"{label} visible before the task opened", kws + ["before", "start"], [r])
                self.add(a, f"{label} visible once the task opened", kws + ["after", "down"], [r])
                if b and a is not None:
                    pct = round(100 * (1 - a / b))
                    self.add(pct, f"% of {label} narrowed away", kws + ["fewer", "less", "cut", "reduc", "%"], [r])
        by_tool: dict[str, list[dict[str, Any]]] = {}
        by_rule: dict[str, list[dict[str, Any]]] = {}
        by_agent: dict[str, list[dict[str, Any]]] = {}
        for r in calls:
            by_tool.setdefault(str(r.get("tool")), []).append(r)
            by_rule.setdefault(str(r.get("rule") or "").split(" (", 1)[0], []).append(r)
            by_agent.setdefault(str(r.get("agent")), []).append(r)
        for agent, rs in by_agent.items():
            scope = {agent}
            for subset, label, kws in ((rs, "calls", ["call", "attempt", "request", "operation", "action"]),
                                       ([r for r in rs if r.get("executed")], "calls that ran",
                                        ["ran", "run", "executed", "succeed", "completed", "operation", "call"]),
                                       ([r for r in rs if r.get("verb") == "BLOCK"], "calls blocked",
                                        ["block", "denied", "stopped", "refused", "rejected"]),
                                       ([r for r in rs if r.get("verb") == "ALLOW"], "calls allowed", ["allow", "permitted"]),
                                       ([r for r in rs if r.get("outside_task")], "out-of-task attempts",
                                        ["outside", "out-of-task", "attempt", "out-of-scope"])):
                self.add(len(subset), f"{label} by {agent}", kws, subset, scope)
            per_tool: dict[str, list[dict[str, Any]]] = {}
            for r in rs:
                per_tool.setdefault(str(r.get("tool")), []).append(r)
            for tool, trs in per_tool.items():
                short = tool.rsplit(".", 1)[-1]
                kws = [short, tool, "call", "read", "time", "request", "operation"]
                self.add(len(trs), f"calls by {agent} to {tool}", kws, trs, {agent, tool, short})
                ran = [r for r in trs if r.get("executed")]
                self.add(len(ran), f"calls by {agent} to {tool} that ran", kws + ["ran", "executed"], ran, {agent, tool, short})
        for group, label in ((by_tool, "calls to"), (by_rule, "calls decided by rule")):
            for name, rs in group.items():
                short = name.rsplit(".", 1)[-1]
                self.add(len(rs), f"{label} {name}", [short, name], rs)
                for v in ("ALLOW", "BLOCK", "ESCALATE"):
                    hit = [r for r in rs if r.get("verb") == v]
                    if hit:
                        self.add(len(hit), f"{label} {name}, {v}", [short, name], hit)
        for r in rows:
            for key, value in (r.get("args") or {}).items():
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    words = re.split(r"[_\W]+", key.lower())
                    self.add(value, f"{key} in the arguments of #{r['seq']}", words + [key.lower(), str(r.get("tool") or "")] +
                             (["₹", "inr", "rupee", "refund", "amount"] if "amount" in key or "inr" in key else []), [r])
        for seq, label, text in self.corpus:
            for m in NUM_RE.finditer(text):
                self.add(m.group(2), f"stated in the {label} of #{seq}", content_words(text), [seq], stated=True)

    def extra(self, value: Any, label: str, keywords: list[str], seqs: list[int]) -> None:
        self.add(value, label, keywords, seqs)

    def extra_name(self, name: str, seqs: list[int]) -> None:
        self.names.setdefault(name, set()).update(seqs or [0])
        self.primary.setdefault(name, set()).update(seqs)

    def support(self, seqs: tuple[int, ...] | list[int] | set[int], note: str, limit: int = 8) -> list[Support]:
        return [Support(s, self.hash_of.get(s, ""), note) for s in sorted(seqs)[:limit]]

    def find_quote(self, quote: str) -> list[Support]:
        q = norm(quote).strip(" .,;:")
        if len(q) < 3:
            return []
        hits = [(seq, label) for seq, label, text in self.corpus if q in text]
        return [Support(seq, self.hash_of.get(seq, ""), f'{label} quoted verbatim') for seq, label in hits[:4]]

    def find_name(self, name: str) -> list[Support]:
        name = name.strip().strip(".,;:")
        if HEX_RE.match(name.lower()):
            for en in self.entries:
                for key in ("hash", "args_digest", "prev_hash"):
                    if str(en.get(key, "")).startswith(name.lower()):
                        return [Support(en["seq"], en.get("hash", ""), f"{key} prefix")]
            return []
        seqs = self.names.get(name)
        if seqs is None:
            return []
        rows = sorted(self.primary.get(name, set())) or sorted(s for s in seqs if s)
        if not rows:
            return [Support(0, self.hash_of.get(0, ""), f"`{name}` in the header / policy in force")]
        return self.support(rows, f"`{name}` appears here", limit=3)


def split_claims(text: str) -> list[str]:
    """Sentences, without splitting inside quotes or backticks."""
    out, buf, quote, tick = [], [], False, False
    i = 0
    while i < len(text):
        ch = text[i]
        buf.append(ch)
        if ch == "`":
            tick = not tick
        elif ch in "\"“”" and not tick:
            quote = (ch == "“") or (ch == '"' and not quote)
            if ch == "”":
                quote = False
        elif ch in ".!?\n" and not quote and not tick:
            nxt = text[i + 1:i + 2]
            if ch == "\n" or nxt == "" or nxt.isspace():
                if not re.search(r"\b(?:e\.g|i\.e|vs|Rs|Art|No)\.$", "".join(buf[-6:])):
                    out.append("".join(buf))
                    buf = []
        i += 1
    out.append("".join(buf))
    return [re.sub(r"^\s*(?:[-*•]|\d+[.)])\s+", "", s).strip() for s in out if s.strip(" \n-*•")]


def fits(keyword: str, window: list[str]) -> bool:
    if " " in keyword:
        return keyword in " ".join(window)
    if len(keyword) == 1:
        return any(keyword in w for w in window)
    return any(w.startswith(keyword) or w.endswith("." + keyword) for w in window)


def check_claim(text: str, section: str, facts: RecordFacts) -> Claim:
    claim = Claim(text, section)
    anchors = 0
    rest = text
    mentioned: list[str] = []
    quoted_at: set[int] = set()
    row_refs: set[int] = set()
    lowered = set(re.findall(r"[a-z]+", text.lower()))
    done, blocked = bool(lowered & DONE_WORDS), bool(lowered & BLOCK_WORDS)
    for m in QUOTE_RE.finditer(text):
        quote = m.group(1) or m.group(2)
        hits = facts.find_quote(quote)
        if not hits:
            claim.reason = f'the quote "{quote[:80]}" does not appear verbatim in the record'
            return claim
        claim.supports += hits
        quoted_at |= {h.seq for h in hits}
        anchors += 1
        rest = rest.replace(m.group(0), " ")
    for m in TICK_RE.finditer(rest):
        token = m.group(1).strip()
        hits = facts.find_name(token) or facts.find_quote(token)
        if not hits:
            claim.reason = f"`{token}` is not a tool, rule, agent or line in the record"
            return claim
        mentioned.append(token)
        claim.supports += hits
        anchors += 1
    rest = TICK_RE.sub(" ", rest)
    for m in NAME_RE.finditer(rest):
        token = m.group(1).rstrip(".-")
        if token.lower() in NOT_NAMES or re.fullmatch(r"[\d.]+", token):
            continue
        hits = facts.find_name(token)
        if not hits:
            claim.reason = f"{token} is not a tool, rule or agent in the record"
            return claim
        mentioned.append(token)
        claim.supports += hits
        anchors += 1
    rest = NAME_RE.sub(" ", rest)
    upper = text.upper()
    for word in VERDICTS:
        if re.search(rf"(?<![\w-]){re.escape(word)}(?![\w-])", text):
            if facts.verdict and word != facts.verdict and not (word == "GO" and "GO-LIVE" in upper):
                claim.reason = f"states the verdict {word}; the record's verdict is {facts.verdict}"
                return claim
            if word == facts.verdict:
                claim.supports.append(Support(len(facts.entries) - 1, facts.final_hash,
                                              f"verdict {word} computed from the whole record"))
                anchors += 1
            break
    for m in SEQ_RE.finditer(rest):
        seq = int(m.group(1))
        if seq not in facts.hash_of or seq == 0:
            claim.reason = f"row #{seq} does not exist in the record"
            return claim
        terms = facts.row_terms.get(seq, set())
        if mentioned and seq not in quoted_at and not any(n in terms or n.rsplit(".", 1)[-1] in terms for n in mentioned):
            row = facts.rows[seq - 1] if 0 < seq <= len(facts.rows) else {}
            claim.reason = (f"row #{seq} is {row.get('kind')} {row.get('tool') or ''} {row.get('verb') or ''}".rstrip()
                            + ", not about " + ", ".join(mentioned))
            return claim
        claim.supports.insert(0, Support(seq, facts.hash_of[seq], f"row #{seq} named in the claim"))
        row_refs.add(seq)
        anchors += 1
    named_agents = {n for n in mentioned if n in facts.agents}
    named_tools = {n for n in mentioned if n in facts.tools}
    ctx = QUOTE_RE.sub(" quote ", text)
    skip = [m.span() for rx in (TICK_RE, NAME_RE, SEQ_RE) for m in rx.finditer(ctx)]
    words = [w.strip("`.,;:()") for w in WORD_RE.findall(ctx.lower().replace("`", " "))]
    numbers: list[tuple[Decimal, int, str]] = []
    for m in NUM_RE.finditer(ctx):
        if any(a <= m.start() < b for a, b in skip):
            continue
        value = to_decimal(m.group(2))
        if value is not None:
            numbers.append((value, len(WORD_RE.findall(ctx[:m.start()].lower().replace("`", " "))), m.group(0).strip()))
    for idx, w in enumerate(words):
        if w in NUMBER_WORDS:
            numbers.append((Decimal(NUMBER_WORDS[w]), idx, w))
    for value, idx, shown in numbers:
        window = words[max(0, idx - WINDOW):idx + WINDOW + 1]
        same = [f for f in facts.facts if f.value == value]
        if named_agents:
            same = [f for f in same if (len(named_agents) > 1 and f.scope & ALL_AGENTS) or (f.scope & named_agents and
                                                                 (not named_tools or f.scope & named_tools))]
        else:
            same = [f for f in same if not f.scope or f.scope & ALL_AGENTS]
        if done and not blocked:
            same = [f for f in same if not f.stated]
        tight = words[idx + 1:idx + 3]
        fitting = [f for f in same if any(fits(k, tight if f.scope & ALL_AGENTS else window) for k in f.keywords)]
        if not fitting and named_agents:
            claim.reason = (f"{shown}: no count for {', '.join(sorted(named_agents))} in the record is {value}")
            return claim
        if not fitting:
            if same:
                claim.reason = (f"{shown}: in the record {value} is the number of {same[0].label}, "
                                "not what this sentence says")
            else:
                claim.reason = f"{shown} is not a count or amount computed from the record"
            return claim
        best = max(fitting, key=lambda f: (not f.stated, sum(fits(k, window) for k in f.keywords), -(len(f.seqs) or 99)))
        claim.supports += facts.support(best.seqs or (0,), f"{value} = {best.label}")
        if " in the arguments of #" in best.label:
            row_refs.update(best.seqs)
        anchors += 1
    for seq in sorted(row_refs) if len(row_refs) == 1 else ():
        row = facts.rows[seq - 1] if 0 < seq <= len(facts.rows) else {}
        if row.get("kind") != "call":
            continue
        if done and not blocked and not row.get("executed"):
            claim.reason = f"says it happened, but #{seq} ({row.get('tool')}) did not run: {row.get('verb')}"
            return claim
        if blocked and not done and row.get("verb") != "BLOCK":
            claim.reason = f"says it was stopped, but #{seq} ({row.get('tool')}) was {row.get('verb')}"
            return claim
    if not anchors:
        claim.reason = "states nothing the record can confirm (no count, quote or record name)"
    seen: set[tuple[int, str]] = set()
    claim.supports = [s for s in claim.supports if (s.seq, s.note) not in seen and not seen.add((s.seq, s.note))]
    return claim


def check_draft(draft: dict[str, list[str]], facts: RecordFacts) -> list[Claim]:
    claims = []
    for section, sentences in draft.items():
        for sentence in sentences:
            for text in split_claims(str(sentence)):
                claims.append(check_claim(text, section, facts))
    return claims

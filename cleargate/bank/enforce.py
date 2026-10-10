"""Session-bound enforcement for the bank voice agent, on the same Enforcer seam as the incident team.

The bank layer resolves the caller from caller ID against the core-banking mirror (not through an agent),
binds `${caller_phone}`, `${customer_id}` and `${account_on_file}` into the policy.yaml rules, and declares
the task intent at task open. AgntID (or its labelled local simulation) decides every call; ClearGate adds no check of its own. The payee
check is the bank system's, inside refund_to_account."""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any

import yaml

from cleargate.approval import ApprovalBroker
from cleargate.enforcement import (ApprovalEvidence, DelegationContext, EnforcementClient, Enforcer,
                                   LocalPolicyStandIn, Outcome, Recorder, TaskOpen)
from cleargate.events import Kind, Verb
from cleargate.policy import Policy
from cleargate.bank.store import PAYEE_ERROR
from cleargate.tools.base import ToolClient, ToolSpec

REFUND = "payments.refund_to_account"

FAILED_CUES = re.compile(r"fail|debit|deduct|stuck|not (?:been )?credited|refund|reverse|kat (?:gay|liy)|"
                         r"cut ho|wapas|vapas|nahi pahu|nahin pahu|atak|अटक|कट|वापस|फेल|रिफंड", re.I)
TRANSFER_CUES = re.compile(r"\b(?:send|transfer|move|bhej|bhejo|daal|dalo|karo transfer)\b|भेज|ट्रांसफर", re.I)


def classify_intent(text: str) -> str:
    """Rules matcher for the caller's opening request."""
    if FAILED_CUES.search(text or ""):
        return "failed_payment"
    if TRANSFER_CUES.search(text or ""):
        return "transfer"
    if re.search(r"statement|स्टेटमेंट", text or "", re.I):
        return "statement"
    return "general"


INTENT_LABEL = {"failed_payment": "a failed payment", "transfer": "a transfer of money",
                "statement": "a statement", "general": "a general enquiry"}


@dataclass
class Session:
    caller_phone: str
    intent: str
    customer: dict[str, Any] = field(default_factory=dict)
    account: dict[str, Any] = field(default_factory=dict)
    failed: list[dict[str, Any]] = field(default_factory=list)
    payment_task_open: bool = False

    @property
    def customer_id(self) -> str:
        return str(self.customer.get("customer_id") or "")

    @property
    def account_on_file(self) -> str:
        return str(self.account.get("account_number") or "")

    def bindings(self) -> dict[str, str]:
        return {"caller_phone": self.caller_phone, "customer_id": self.customer_id,
                "account_on_file": self.account_on_file}

    @classmethod
    def resolve(cls, inner: ToolClient, phone: str, transcript: str) -> Session:
        """Trusted caller-ID screen pop, straight from the system of record (not through an agent)."""
        session = cls(phone, classify_intent(transcript))
        found = inner.call("payments.get_customer", {"phone": phone})
        if not found.ok:
            return session
        session.customer = found.content
        account = inner.call("payments.get_account", {"customer_id": session.customer_id})
        session.account = account.content if account.ok else {}
        failed = inner.call("payments.get_failed_payment", {"customer_id": session.customer_id})
        session.failed = list((failed.content or {}).get("failed_payments") or []) if failed.ok else []
        return session


def bank_section(policy: Policy) -> dict[str, Any]:
    raw = yaml.safe_load(open(policy.source_path).read()) or {}
    return raw.get("bank") or {}


def _bind(value: Any, bindings: dict[str, str]) -> Any:
    if isinstance(value, str):
        return re.sub(r"\$\{(\w+)\}", lambda m: bindings.get(m.group(1)) or f"<unbound:{m.group(1)}>", value)
    if isinstance(value, list):
        return [_bind(v, bindings) for v in value]
    if isinstance(value, dict):
        return {k: _bind(v, bindings) for k, v in value.items()}
    return value


def bank_policy(policy: Policy, session: Session) -> Policy:
    """policy.yaml with the bank section's visibility and delegations, and the session values bound in."""
    section = bank_section(policy)
    visible = tuple(section.get("visible_before_payment_task") or ()) + tuple(section.get("visible_once_payment_task") or ())
    rules = tuple(replace(r, where=_bind(r.where, session.bindings())) if r.where else r for r in policy.rules)
    task = section.get("task") or {}
    return replace(policy, visible_tools=visible, rules=rules,
                   delegations={k: tuple(v or []) for k, v in (section.get("delegations") or {}).items()},
                   task_name=task.get("name", policy.task_name), task_intent=task.get("intent", policy.task_intent))


TASK_INTENT = "failed-payment enquiry for the caller's own account"
BANK_SYSTEM = "bank-system-payee-check"
SIMULATED = {"visibility": "local-simulation: AgntID tool visibility",
             "intent-mismatch": "local-simulation: AgntID Intent-Based Controls",
             "bank-refund-within-cap": "local-simulation: AgntID Parameter-Level Policy"}


class BankEnforcer:
    """ClearGate blocks nothing here. Under AgntID every decision is the runtime's; the local stand-in simulates
    visibility, intent and the amount cap, labelled as simulation. The payee check belongs to the bank system
    (refund_to_account itself); its refusals are labelled `bank-system-payee-check`."""

    def __init__(self, inner: Enforcer, policy: Policy, session: Session):
        self.inner = inner
        self.policy = policy
        self.session = session
        self.source = inner.source
        self.simulate = isinstance(inner, LocalPolicyStandIn)
        section = bank_section(policy)
        self.before = tuple(section.get("visible_before_payment_task") or ())
        self.once = tuple(section.get("visible_once_payment_task") or ())
        self.cap = int(section.get("refund_cap_inr") or 5000)

    def visible(self) -> set[str]:
        return set(self.before) | (set(self.once) if self.session.payment_task_open else set())

    def open_task(self, user_id: str, prompt: str, tools: list[ToolSpec]) -> TaskOpen:
        opened = self.inner.open_task(user_id, f"{prompt}\nTask intent: {TASK_INTENT}", tools)
        details = opened.details | {"task_intent": TASK_INTENT}
        if not self.simulate:
            return replace(opened, details=details)
        allowed = self.visible()
        visible = [t for t in opened.visible if t.name in allowed]
        return replace(opened, visible=visible, relevant_tool_count=len(visible),
                       details=details | {"engine": SIMULATED["visibility"],
                                          "relevant_tool_names": [t.name for t in visible]})

    def open_delegation(self, parent: DelegationContext, agent: str, instruction: str) -> DelegationContext:
        return self.inner.open_delegation(parent, agent, instruction)

    def close_task(self, task_id: str) -> None:
        self.inner.close_task(task_id)

    def simulated(self, agent: str, tool: str, args: dict[str, Any]) -> list[tuple[str, str]]:
        """What the AgntID runtime would decide, approximated for the local stand-in only."""
        s = self.session
        if tool not in self.visible():
            return [("visibility", f"{tool} stays hidden until a payment task is open; the caller asked about "
                                   f"{INTENT_LABEL.get(s.intent, s.intent)}")]
        if tool != REFUND:
            return []
        intent: list[tuple[str, str]] = []
        payment = {p["payment_id"]: p for p in s.failed}.get(str(args.get("payment_id")))
        try:
            amount = int(args.get("amount_inr") or 0)
        except (TypeError, ValueError):
            amount = 0
        if s.intent != "failed_payment":
            intent.append(("intent-mismatch", f"the caller asked about {INTENT_LABEL.get(s.intent, s.intent)}, "
                                              "not a failed payment"))
        if payment is None:
            intent.append(("intent-mismatch", f"{args.get('payment_id')} is not one of this caller's failed payments"))
        elif amount > int(payment["amount_inr"]) - int(payment.get("refunded_inr") or 0):
            done = int(payment.get("refunded_inr") or 0)
            intent.append(("intent-mismatch", f"₹{amount:,} is more than the ₹{int(payment['amount_inr']):,} "
                                              f"failed debit on {payment['payment_id']}"
                                              + (f" (₹{done:,} already refunded)" if done else "")))
        maker_checker = self.policy.evaluate(agent, tool, args).verb is Verb.ESCALATE
        if amount > self.cap and (intent or not maker_checker):
            return [("bank-refund-within-cap", f"₹{amount:,} is over the ₹{self.cap:,} amount_inr limit"), *intent]
        return intent

    def invoke(self, ctx: DelegationContext, tool: str, args: dict[str, Any], inner: ToolClient,
               approval: ApprovalEvidence | None) -> Outcome:
        if self.simulate:
            sims = self.simulated(ctx.agent, tool, args)
            if sims:
                rule = sims[0][0]
                return Outcome(Verb.BLOCK, rule, "; ".join(f"[{SIMULATED[r]}] {why}" for r, why in sims),
                               details={"denial_step": SIMULATED[rule], "stage": SIMULATED[rule], "bank_check": True,
                                        "intent_mismatch": next((w for r, w in sims if r == "intent-mismatch"), ""),
                                        "simulated": [r for r, _ in sims]})
        outcome = self.inner.invoke(ctx, tool, args, inner, approval)
        if outcome.result is not None and not outcome.result.ok and PAYEE_ERROR in str(outcome.result.error):
            return replace(outcome, details=outcome.details | {"denial_step": BANK_SYSTEM, "stage": BANK_SYSTEM})
        return outcome


class BankGate(EnforcementClient):
    def __init__(self, inner: ToolClient, recorder: Recorder, policy: Policy, enforcer: BankEnforcer,
                 broker: ApprovalBroker):
        super().__init__(inner, recorder, policy, enforcer, broker)
        self.bank = enforcer

    def open_payment_task(self, ctx: DelegationContext, why: str) -> None:
        if self.bank.session.intent != "failed_payment" or not self.bank.session.failed:
            label = f"[{SIMULATED['visibility']}] " if self.bank.simulate else ""
            self.recorder.emit(ctx, Kind.NOTICE, Verb.NARROW, rule="payment-task-not-opened",
                               reason=f"{label}no payment task: the caller asked about "
                                      f"{INTENT_LABEL.get(self.bank.session.intent)}; refund tools stay hidden")
            return
        self.bank.session.payment_task_open = True
        if not self.bank.simulate:
            self.recorder.emit(ctx, Kind.NOTICE, Verb.NARROW, rule="payment-task-open",
                               reason=f"payment task opened ({why}); visibility is the AgntID runtime's")
            return
        allowed = self.bank.visible()
        self._visible = [t for t in self._all_tools if t.name in allowed]
        self.recorder.emit(ctx, Kind.NOTICE, Verb.NARROW, rule="payment-task-open",
                           reason=f"[{SIMULATED['visibility']}] payment task opened ({why}); now visible: "
                                  f"{', '.join(self.bank.once)}",
                           meta={"visible": [t.name for t in self._visible], "stage": SIMULATED["visibility"]})

    def _outside_task(self, ctx: DelegationContext, tool: str, args: dict[str, Any], outcome: Outcome) -> bool:
        if outcome.details.get("bank_check"):
            return True
        return super()._outside_task(ctx, tool, args, outcome)


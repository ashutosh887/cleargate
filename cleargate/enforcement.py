from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from cleargate.approval import ApprovalBroker, ApprovalRequest
from cleargate.bus import EventBus
from cleargate.canonical import arguments_digest
from cleargate.events import Decision, Kind, Verb
from cleargate.policy import Policy
from cleargate.record import SignedRecord
from cleargate.tools.base import ToolClient, ToolResult, ToolSpec

LOCAL_SOURCE = "local-policy-stand-in (not AgntID)"
STOCK_SOURCE = "stock (no enforcement)"


@dataclass(frozen=True)
class DelegationContext:
    task_id: str
    agent: str
    chain: tuple[str, ...]
    delegation_id: str = ""
    parent_delegation_id: str = ""
    constraints: tuple[str, ...] = ()
    instruction: str = ""
    tool_allowlist: tuple[str, ...] = ()


@dataclass(frozen=True)
class ApprovalEvidence:
    required: bool = True
    decision: str = ""
    approver_id: str = ""
    decision_id: str = ""
    operation_id: str = ""
    source: str = ""
    tool_name: str = ""
    arguments_digest: str = ""
    issued_at: str = ""
    expires_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TaskOpen:
    task_id: str
    visible: list[ToolSpec]
    eligible_tool_count: int
    relevant_tool_count: int
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Outcome:
    verb: Verb
    rule: str
    reason: str
    result: ToolResult | None = None
    operation_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)


def delegation_id_for(task_id: str, agent: str, instruction: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"agntid:{task_id}:{agent}\x1f{instruction}"))


class Enforcer(Protocol):
    source: str

    def open_task(self, user_id: str, prompt: str, tools: list[ToolSpec]) -> TaskOpen: ...

    def open_delegation(self, parent: DelegationContext, agent: str, instruction: str) -> DelegationContext: ...

    def invoke(self, ctx: DelegationContext, tool: str, args: dict[str, Any], inner: ToolClient,
               approval: ApprovalEvidence | None) -> Outcome: ...

    def close_task(self, task_id: str) -> None: ...


class LocalPolicyStandIn:
    source = LOCAL_SOURCE

    def __init__(self, policy: Policy):
        self.policy = policy
        self._closed: set[str] = set()
        self._used_decisions: set[str] = set()
        self._lock = threading.Lock()

    def open_task(self, user_id: str, prompt: str, tools: list[ToolSpec]) -> TaskOpen:
        allowed = set(self.policy.visible_tools)
        visible = [t for t in tools if t.name in allowed] if allowed else list(tools)
        return TaskOpen(str(uuid.uuid4()), visible, len(tools), len(visible),
                        {"engine": "policy.yaml visible_tools", "relevant_tool_names": [t.name for t in visible]})

    def open_delegation(self, parent: DelegationContext, agent: str, instruction: str) -> DelegationContext:
        constraints = tuple(dict.fromkeys(parent.constraints + self.policy.constraints_for(agent)))
        return DelegationContext(parent.task_id, agent, parent.chain + (agent,),
                                 delegation_id_for(parent.task_id, agent, instruction),
                                 parent.delegation_id, constraints, instruction)

    def invoke(self, ctx: DelegationContext, tool: str, args: dict[str, Any], inner: ToolClient,
               approval: ApprovalEvidence | None) -> Outcome:
        with self._lock:
            if ctx.task_id in self._closed:
                return Outcome(Verb.BLOCK, "task-closed", "Task expired or closed", details={"denial_step": "task_resolution"})
        verdict = self.policy.evaluate(ctx.agent, tool, args, ctx.constraints)
        step = "delegation" if verdict.rule.startswith("delegation") else "policy_evaluation"
        if verdict.verb is Verb.BLOCK:
            return Outcome(Verb.BLOCK, verdict.rule, verdict.reason, details={"denial_step": step})
        if verdict.verb is Verb.ESCALATE:
            if approval is None:
                return Outcome(Verb.ESCALATE, verdict.rule, verdict.reason, operation_id=uuid.uuid4().hex[:12],
                               details={"status": "REVIEW_REQUIRED", "approver_role": verdict.approver})
            refusal = self._check_evidence(tool, args, approval)
            if refusal:
                return Outcome(Verb.BLOCK, "approval-evidence", refusal, details={"denial_step": "approval"})
        result = inner.call(tool, args)
        rule = f"{verdict.rule} (approved by {approval.approver_id})" if approval else verdict.rule
        return Outcome(Verb.ALLOW, rule, verdict.reason, result)

    def _check_evidence(self, tool: str, args: dict[str, Any], approval: ApprovalEvidence) -> str:
        actual = arguments_digest(args)
        if approval.decision != "approved":
            return f"approval decision is {approval.decision or 'missing'}"
        if approval.tool_name != tool:
            return f"approval covers {approval.tool_name}, not {tool}"
        if approval.arguments_digest != actual:
            return (f"approval is bound to arguments digest {approval.arguments_digest[:12]}…; "
                    f"these arguments hash to {actual[:12]}…")
        if approval.expires_at and float(approval.expires_at) < time.time():
            return "approval expired"
        with self._lock:
            if approval.decision_id in self._used_decisions:
                return "approval already used once"
            self._used_decisions.add(approval.decision_id)
        return ""

    def close_task(self, task_id: str) -> None:
        with self._lock:
            self._closed.add(task_id)


class Recorder:
    def __init__(self, bus: EventBus, record: SignedRecord, run_id: str, mode: str, source: str):
        self.bus = bus
        self.record = record
        self.run_id = run_id
        self.mode = mode
        self.source = source

    def emit(self, ctx: DelegationContext, kind: Kind, verb: Verb, **fields: Any) -> Decision:
        decision = Decision(kind=kind, verb=verb, source=self.source, run_id=self.run_id, mode=self.mode,
                            task_id=ctx.task_id, agent=ctx.agent, delegation_chain=list(ctx.chain), **fields)
        payload = decision.to_dict()
        entry = self.record.append(payload)
        self.bus.publish({"type": "decision", **payload, "args_digest": entry.get("args_digest"), "seq": entry["seq"]})
        return decision


class AgentToolView:
    def __init__(self, gate: BaseGate, ctx: DelegationContext):
        self._gate = gate
        self.ctx = ctx

    def list_tools(self) -> list[ToolSpec]:
        return self._gate.visible_tools()

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        return self._gate.call(self.ctx, name, args)


def tool_stats(tools: list[ToolSpec]) -> dict[str, Any]:
    schema_chars = len(json.dumps([t.to_openai() for t in tools]))
    return {"visible_tools": len(tools), "github_tools": sum(t.server == "github" for t in tools),
            "approx_context_tokens": schema_chars // 4}


class BaseGate:
    mode = "base"

    def __init__(self, inner: ToolClient, recorder: Recorder, policy: Policy):
        self.inner = inner
        self.recorder = recorder
        self.policy = policy
        self._all_tools = inner.list_tools()
        self._visible = list(self._all_tools)

    def visible_tools(self) -> list[ToolSpec]:
        return list(self._visible)

    def bind(self, ctx: DelegationContext) -> AgentToolView:
        return AgentToolView(self, ctx)

    def open_task(self, user: str, prompt: str) -> DelegationContext:
        raise NotImplementedError

    def delegate(self, parent: DelegationContext, agent: str, instruction: str) -> DelegationContext:
        raise NotImplementedError

    def call(self, ctx: DelegationContext, tool: str, args: dict[str, Any]) -> ToolResult:
        raise NotImplementedError

    def close_task(self, ctx: DelegationContext) -> None:
        raise NotImplementedError


class StockClient(BaseGate):
    mode = "stock"

    def __init__(self, inner: ToolClient, recorder: Recorder, policy: Policy):
        super().__init__(inner, recorder, policy)
        self._closed: set[str] = set()

    def open_task(self, user: str, prompt: str) -> DelegationContext:
        ctx = DelegationContext(str(uuid.uuid4()), "orchestrator", (f"user:{user}", "orchestrator"))
        stats = tool_stats(self._visible)
        self.recorder.emit(ctx, Kind.TASK_OPEN, Verb.UNGUARDED,
                           reason=f"no narrowing: {stats['github_tools']} GitHub tools visible",
                           meta={"after": stats, "before": stats, "prompt": prompt})
        return ctx

    def delegate(self, parent: DelegationContext, agent: str, instruction: str) -> DelegationContext:
        ctx = DelegationContext(parent.task_id, agent, parent.chain + (agent,), instruction=instruction)
        self.recorder.emit(ctx, Kind.DELEGATION, Verb.UNGUARDED,
                           reason="constraints passed as prompt text only", meta={"instruction": instruction})
        return ctx

    def call(self, ctx: DelegationContext, tool: str, args: dict[str, Any]) -> ToolResult:
        observed = self.policy.evaluate(ctx.agent, tool, args, self.policy.constraints_for(ctx.agent))
        closed = ctx.task_id in self._closed
        outside = closed or observed.verb in (Verb.BLOCK, Verb.ESCALATE)
        result = self.inner.call(tool, args)
        self.recorder.emit(ctx, Kind.CALL, Verb.UNGUARDED, tool=tool, args=args, executed=result.ok,
                           outside_task=outside, rule=("task-closed" if closed else observed.rule) if outside else "",
                           reason="outside the task and it reached the tool" if outside else "",
                           result_preview=result.preview(), meta={"policy_classifies_as": str(observed.verb)})
        return result

    def close_task(self, ctx: DelegationContext) -> None:
        self._closed.add(ctx.task_id)
        self.recorder.emit(ctx, Kind.TASK_CLOSE, Verb.UNGUARDED, reason="task closed; agents keep their credentials")


class EnforcementClient(BaseGate):
    mode = "gated"

    def __init__(self, inner: ToolClient, recorder: Recorder, policy: Policy, enforcer: Enforcer,
                 broker: ApprovalBroker, approval_ttl: float = 300.0):
        super().__init__(inner, recorder, policy)
        self.enforcer = enforcer
        self.broker = broker
        self.approval_ttl = approval_ttl
        self._evidence: dict[tuple[str, str, str], ApprovalEvidence] = {}
        self._lock = threading.Lock()

    def open_task(self, user: str, prompt: str) -> DelegationContext:
        opened = self.enforcer.open_task(user, prompt, self._all_tools)
        self._visible = opened.visible
        ctx = DelegationContext(opened.task_id, "orchestrator", (f"user:{user}", "orchestrator"))
        before, after = tool_stats(self._all_tools), tool_stats(self._visible)
        self.recorder.emit(ctx, Kind.TASK_OPEN, Verb.NARROW, rule="task-open",
                           reason=f"{before['github_tools']} GitHub tools → {after['github_tools']} for this task",
                           meta={"before": before, "after": after, "prompt": prompt,
                                 "eligible_tool_count": opened.eligible_tool_count,
                                 "relevant_tool_count": opened.relevant_tool_count,
                                 "visible": [t.name for t in self._visible], **opened.details})
        return ctx

    def delegate(self, parent: DelegationContext, agent: str, instruction: str) -> DelegationContext:
        ctx = self.enforcer.open_delegation(parent, agent, instruction)
        self.recorder.emit(ctx, Kind.DELEGATION, Verb.ALLOW, rule="delegation-open",
                           reason=f"constraints carried: {', '.join(ctx.constraints) or 'none'}",
                           meta={"instruction": instruction, "constraints": list(ctx.constraints),
                                 "delegation_id": ctx.delegation_id, "parent_delegation_id": ctx.parent_delegation_id})
        return ctx

    def call(self, ctx: DelegationContext, tool: str, args: dict[str, Any]) -> ToolResult:
        key = (ctx.task_id, ctx.agent, tool)
        with self._lock:
            held = self._evidence.get(key)
        outcome = self.enforcer.invoke(ctx, tool, args, self.inner, held)
        if outcome.verb is Verb.ESCALATE and held is None:
            escalated = self._escalate(ctx, tool, args, outcome)
            if escalated is None:
                return ToolResult(False, None, "REJECTED by the approver")
            outcome, held = escalated
        return self._settle(ctx, tool, args, outcome, held.approver_id if held else None)

    def close_task(self, ctx: DelegationContext) -> None:
        self.enforcer.close_task(ctx.task_id)
        self.recorder.emit(ctx, Kind.TASK_CLOSE, Verb.BLOCK, rule="task-close",
                           reason="task closed; every later call is blocked")

    def _settle(self, ctx: DelegationContext, tool: str, args: dict[str, Any], outcome: Outcome,
                approver: str | None) -> ToolResult:
        if outcome.verb is Verb.ALLOW and outcome.result is not None:
            self.recorder.emit(ctx, Kind.CALL, Verb.ALLOW, tool=tool, args=args, rule=outcome.rule,
                               reason=outcome.reason, executed=outcome.result.ok, approver=approver,
                               result_preview=outcome.result.preview(), meta=outcome.details)
            return outcome.result
        self.recorder.emit(ctx, Kind.CALL, Verb.BLOCK, tool=tool, args=args, rule=outcome.rule,
                           reason=outcome.reason, outside_task=True, meta=outcome.details)
        return ToolResult(False, None, f"BLOCKED by {outcome.rule}: {outcome.reason}")

    def _escalate(self, ctx: DelegationContext, tool: str, args: dict[str, Any],
                  first: Outcome) -> tuple[Outcome, ApprovalEvidence] | None:
        digest = arguments_digest(args)
        self.recorder.emit(ctx, Kind.CALL, Verb.ESCALATE, tool=tool, args=args, rule=first.rule, reason=first.reason,
                           meta=first.details | {"operation_id": first.operation_id})
        answer = self.broker.request(ApprovalRequest(self.recorder.run_id, self.mode, ctx.agent, tool, args, digest,
                                                     first.rule, first.reason, list(ctx.chain)))
        self.recorder.emit(ctx, Kind.APPROVAL, Verb.ALLOW if answer.approved else Verb.BLOCK, tool=tool, args=args,
                           rule=first.rule, approver=answer.approver_id, outside_task=not answer.approved,
                           reason=f"{'approved' if answer.approved else 'rejected'} via {answer.via}")
        if not answer.approved:
            return None
        now = time.time()
        evidence = ApprovalEvidence(True, "approved", answer.approver_id, uuid.uuid4().hex, first.operation_id,
                                    f"cleargate:{answer.via}", tool, digest, f"{now:.0f}", f"{now + self.approval_ttl:.0f}")
        with self._lock:
            self._evidence[(ctx.task_id, ctx.agent, tool)] = evidence
        return self.enforcer.invoke(ctx, tool, args, self.inner, evidence), evidence

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import threading
from typing import Any

from cleargate.enforcement import (ApprovalEvidence, DelegationContext, Outcome, TaskOpen, allowlist_for,
                                   delegation_id_for)
from cleargate.events import Verb
from cleargate.policy import Policy
from cleargate.tools.base import ToolClient, ToolResult, ToolSpec, from_runtime_name, runtime_name, spec_from_mcp

AGNTID_SOURCE = "agntid"

CONTROL_TOOLS = {"agntid_task_open", "agntid_task_close", "agntid_delegation_open",
                 "agntid_delegation_close", "agntid_action_update"}

DENIAL_KEYS = ("policy_name", "intent_mismatch", "denial_step", "verdict_code", "outcome", "intent_status", "error")


class AgntIDNotWired(RuntimeError):
    pass


class AgntIDEnforcer:
    """Runs every gated call through the AgntID runtime (agntid-sdk 0.2.0).

    Every allow and deny is the runtime's. `policy.yaml` is read for one thing only: which
    calls need a human approval first (its ESCALATE rules). An approved call is re-sent
    through `wrap_client(...).call_tool_async` with the approval evidence attached, so the
    runtime still makes the final decision, and a denial there is recorded as a BLOCK.
    ClearGate executes nothing on its own client unless AGNTID_DIRECT_APPROVED_EXECUTE=1.
    """

    source = AGNTID_SOURCE

    def __init__(self, policy: Policy, mcp_url: str | None = None, access_token: str | None = None):
        try:
            import agntid
        except ImportError as exc:
            raise AgntIDNotWired(
                "agntid-sdk is not installed: pip install git+https://github.com/AGNTID-AI/agntid-python.git") from exc
        self.agntid = agntid
        self.policy = policy
        conf = policy.agntid
        self.agent_id = conf.get("agent_id", "cleargate:v1")
        self.task_argument = conf.get("task_argument", "_task_id")
        self.delegation_argument = conf.get("delegation_argument", "_delegation_id")
        self.approval_argument = conf.get("approval_argument", "agntid_approval")
        self.tool_names: dict[str, str] = conf.get("tool_names") or {}
        self.prefixes: list[str] = list(conf.get("servers") or ["github", "payments", "comms"])
        self.mcp_url = mcp_url or os.environ.get("AGNTID_MCP_URL", "http://localhost:8082/mcp")
        self.access_token = access_token or os.environ.get("AGNTID_ACCESS_TOKEN") or None
        self.review_shape = os.environ.get("AGNTID_REVIEW_SHAPE", "error")
        # Off by default. 1: an approved call runs on ClearGate's own tool client, bypassing the runtime.
        self.direct_approved_execute = os.environ.get("AGNTID_DIRECT_APPROVED_EXECUTE", "0") == "1"
        # Every runtime round trip is bounded, so a hung runtime fails one call instead of the run.
        self.timeout = float(os.environ.get("AGNTID_TIMEOUT_S", "30"))
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, daemon=True, name="agntid-loop").start()
        try:
            self._client = self._run(self._connect())
        except Exception as exc:
            raise AgntIDNotWired(f"cannot reach the AgntID runtime MCP endpoint at {self.mcp_url}: "
                                 f"{type(exc).__name__}: {exc}") from exc
        self._closed: set[str] = set()
        self._users: dict[str, str] = {}
        self._runtime_visible: set[str] = set()
        self._delegations: dict[str, list[str]] = {}
        # Runtime-executed calls bypass ClearGate's tool client, so live GitHub refs are sandboxed here too.
        self.github_sandbox: Any = None

    def _run(self, coro: Any) -> Any:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=self.timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise TimeoutError(f"the AgntID runtime did not answer within {self.timeout:.0f}s") from None

    def _decide(self, coro: Any) -> Outcome:
        """A runtime decision, or BLOCK when the runtime times out: no answer is never an allow."""
        try:
            return self._run(coro)
        except TimeoutError as exc:
            return Outcome(Verb.BLOCK, "agntid-timeout", f"runtime error: {exc}", details={"denial_step": "transport"})

    async def _connect(self) -> Any:
        client = self.agntid.AgntidMCPClient(self.mcp_url, access_token=self.access_token)
        await client.__aenter__()
        return client

    def runtime_name(self, tool: str) -> str:
        return self.tool_names.get(tool) or runtime_name(tool)

    def cleargate_name(self, name: str) -> str:
        reverse = {v: k for k, v in self.tool_names.items()}
        return reverse.get(name) or from_runtime_name(name, self.prefixes)

    def open_task(self, user_id: str, prompt: str, tools: list[ToolSpec]) -> TaskOpen:
        agntid = self.agntid
        runtime_tools = [t for t in self._run(agntid.get_tools_list(self._client)) if _name(t) not in CONTROL_TOOLS]
        self._runtime_visible = {_name(t) for t in runtime_tools}
        task_id = agntid.create_task(self.agent_id, user_id, prompt)
        self._users[task_id] = user_id
        opened = self._run(agntid.send_task_open_details(self._client, task_id, self.agent_id, user_id, prompt))
        if not opened.ok:
            raise AgntIDNotWired(f"agntid_task_open was rejected: {opened.reason or 'no reason given'}")
        details: dict[str, Any] = {"engine": "agntid", "runtime_visible_tool_count": len(runtime_tools)}
        try:
            shortlisted = agntid.filter_tools_for_task(runtime_tools, opened)
            details["intent_prepared"] = True
        except agntid.IntentPreparationError as exc:
            # Standard intent mode (or no engine credential) prepares no snapshot. Degrade to the
            # profile-visible list and say so; the runtime still checks every call.
            shortlisted = runtime_tools
            details |= {"intent_prepared": False, "intent_reason": str(exc)}
        snapshot = opened.snapshot
        # Keep a stock description (it may carry the scenario's poisoned text) so both modes
        # read the same words; the schema is always the runtime's.
        local = {t.name: t for t in tools}
        visible = []
        for t in shortlisted:
            spec = spec_from_mcp(self.cleargate_name(_name(t)), t)
            if spec.name in local and local[spec.name].description != spec.description and "<IMPORTANT>" in local[spec.name].description:
                spec = ToolSpec(spec.name, local[spec.name].description, spec.parameters)
            visible.append(spec)
        # Tools the policy routes through a human (ESCALATE) stay visible to the agent even when
        # the runtime hides them: ClearGate brokers the call, the agent never executes it itself.
        brokered = sorted({t for r in self.policy.rules if r.verb is Verb.ESCALATE for t in r.tools}
                          - {s.name for s in visible})
        visible += [local[n] for n in brokered if n in local]
        details["brokered_by_cleargate"] = [n for n in brokered if n in local]
        details |= {"snapshot_id": getattr(snapshot, "snapshot_id", ""),
                    "intent_engine": getattr(snapshot, "engine_id", ""),
                    "constraints": list(getattr(snapshot, "constraints", ()) or ()),
                    "relevant_tool_names": sorted(_name(t) for t in shortlisted)}
        return TaskOpen(
            task_id, visible,
            opened.eligible_tool_count if opened.eligible_tool_count is not None else len(runtime_tools),
            opened.relevant_tool_count if opened.relevant_tool_count is not None else len(shortlisted),
            details,
        )

    def open_delegation(self, parent: DelegationContext, agent: str, instruction: str) -> DelegationContext:
        agntid = self.agntid
        constraints = tuple(dict.fromkeys(parent.constraints + self.policy.constraints_for(agent)
                                          + tuple(agntid.extract_explicit_constraints(instruction))))
        delegation_id = delegation_id_for(parent.task_id, agent, instruction)
        allowlist = allowlist_for(self.policy, agent)
        context = agntid.DelegationContext(
            delegation_id=delegation_id,
            # The runtime expects the root task's agent_id as the parent of a first-level delegation.
            parent_agent_id=f"{self.agent_id}/{parent.agent}" if parent.delegation_id else self.agent_id,
            acting_agent_id=f"{self.agent_id}/{agent}",
            delegated_intent=agntid.DelegatedIntent(text=instruction, constraints=constraints),
            parent_delegation_id=parent.delegation_id,
            tool_allowlist=tuple(self.runtime_name(t) for t in allowlist),
        )
        try:
            payload = _payload(self._run(agntid.send_delegation_open(self._client, parent.task_id, context)))
            accepted, why = payload.get("ok") is True, payload.get("reason") or json.dumps(payload)[:200]
        except Exception as exc:
            accepted, why = False, f"{type(exc).__name__}: {exc}"
        if not accepted:
            # Calls then run under the root task only; the runtime still checks each one.
            return DelegationContext(parent.task_id, agent, parent.chain + (agent,), "", parent.delegation_id,
                                     constraints, instruction, allowlist,
                                     note=f"runtime did not accept delegation_open ({why}); calls run under the root task")
        self._delegations.setdefault(parent.task_id, []).append(delegation_id)
        return DelegationContext(parent.task_id, agent, parent.chain + (agent,), delegation_id,
                                 parent.delegation_id, constraints, instruction, allowlist)

    def invoke(self, ctx: DelegationContext, tool: str, args: dict[str, Any], inner: ToolClient,
               approval: ApprovalEvidence | None) -> Outcome:
        name = self.runtime_name(tool)
        verdict = self.policy.evaluate(ctx.agent, tool, args, ctx.constraints)
        if verdict.verb is Verb.ESCALATE:
            return self._app_layer_escalate(ctx, tool, name, args, inner, approval, verdict.rule, verdict.reason)
        sandboxed = self._sandbox_args(tool, args)
        if isinstance(sandboxed, Outcome):
            return sandboxed
        call_args = sandboxed | ({self.approval_argument: approval.to_dict()} if approval else {})
        if self.review_shape == "envelope":
            return self._decide(self._invoke_envelope(ctx, name, call_args))
        return self._decide(self._invoke_wrapped(ctx, name, call_args))

    def _app_layer_escalate(self, ctx: DelegationContext, tool: str, name: str, args: dict[str, Any],
                            inner: ToolClient, approval: ApprovalEvidence | None, rule: str, reason: str) -> Outcome:
        if approval is None:
            if name in self._runtime_visible:
                # Never send it unapproved: the runtime would let it run.
                return Outcome(Verb.ESCALATE, rule, reason,
                               details={"status": "REVIEW_REQUIRED", "runtime": "visible to the agent; held by ClearGate"})
            runtime = self._decide(self._invoke_wrapped(ctx, name, dict(args)))
            return Outcome(Verb.ESCALATE, rule, reason,
                           details={"status": "REVIEW_REQUIRED", "runtime_verdict": str(runtime.verb),
                                    "runtime_rule": runtime.rule, "runtime_reason": runtime.reason,
                                    **{f"runtime_{k}": v for k, v in runtime.details.items()}})
        if self.direct_approved_execute:
            result = inner.call(tool, args)
            return Outcome(Verb.ALLOW, f"{rule} (approved by {approval.approver_id})",
                           f"executed by ClearGate's own client (AGNTID_DIRECT_APPROVED_EXECUTE=1), not the "
                           f"runtime, on {approval.approver_id}'s approval of digest {approval.arguments_digest[:4]}…",
                           result, details={"executed_by": "cleargate-direct (runtime bypassed)"})
        sandboxed = self._sandbox_args(tool, args)
        if isinstance(sandboxed, Outcome):
            return sandboxed
        outcome = self._decide(self._invoke_wrapped(ctx, name, sandboxed | {self.approval_argument: approval.to_dict()}))
        details = outcome.details | {"executed_by": "agntid-runtime", "approved_by": approval.approver_id}
        if outcome.verb is Verb.ALLOW:
            return Outcome(Verb.ALLOW, f"{outcome.rule} (approved by {approval.approver_id})", outcome.reason,
                           outcome.result, outcome.operation_id, details)
        return Outcome(Verb.BLOCK, outcome.rule,
                       f"approved by {approval.approver_id}, then denied by the AgntID runtime: {outcome.reason}",
                       operation_id=outcome.operation_id,
                       details=details | {"denial_step": details.get("denial_step") or "runtime_after_approval"})

    def _sandbox_args(self, tool: str, args: dict[str, Any]) -> dict[str, Any] | Outcome:
        if self.github_sandbox is None or not tool.startswith("github."):
            return dict(args)
        from cleargate.tools.github import GitHubSafetyError

        try:
            return self.github_sandbox.check(tool, args)
        except GitHubSafetyError as exc:
            return Outcome(Verb.BLOCK, "live-sandbox-guard", f"refused before the runtime: {exc}",
                           details={"denial_step": "live_sandbox_guard"})

    async def _invoke_wrapped(self, ctx: DelegationContext, name: str, args: dict[str, Any]) -> Outcome:
        agntid = self.agntid
        wrapped = agntid.wrap_client(self._client, ctx.task_id, ctx.delegation_id or None,
                                     task_argument=self.task_argument, delegation_argument=self.delegation_argument)
        agntid.get_last_denial(clear=True)
        try:
            result = await wrapped.call_tool_async(name, args)
        except Exception as exc:
            if self._runtime_visible and name not in self._runtime_visible or "unknown tool" in str(exc).lower():
                return Outcome(Verb.BLOCK, "runtime-profile",
                               f"{name} is not exposed by the AgntID runtime (protection profile, disabled, or "
                               f"high impact); the call never reached the server",
                               details={"denial_step": "tool_visibility", "policy_name": "runtime-profile",
                                        "error": str(exc)[:200]})
            return Outcome(Verb.BLOCK, "agntid-error", f"runtime error: {type(exc).__name__}: {exc}"[:400],
                           details={"denial_step": "transport"})
        if not getattr(result, "denied", False):
            return Outcome(Verb.ALLOW, "agntid-allowed", "allowed by the AgntID runtime", ToolResult(True, _clean(result)))
        denial = agntid.get_last_denial(clear=True) or {}
        details = {k: denial[k] for k in DENIAL_KEYS if denial.get(k)}
        inner_error = _runtime_error(str(denial.get("reason") or getattr(result, "message", "")))
        if inner_error and not denial.get("policy_name"):
            code, message = inner_error
            rule = "classification-pending" if code == "CLASSIFICATION_GATE" else f"runtime:{code.lower()}"
            return Outcome(Verb.BLOCK, rule, message, details=details | {"verdict_code": code, "policy_name": rule,
                                                                          "denial_step": "classification" if code == "CLASSIFICATION_GATE" else "runtime"})
        if denial.get("outcome") == "review_required":
            review = denial.get("review")
            return Outcome(Verb.ESCALATE, denial.get("policy_name") or "review_required",
                           denial.get("reason") or getattr(result, "message", ""),
                           operation_id=getattr(review, "operation_id", ""),
                           details=details | {"status": "REVIEW_REQUIRED", "review_id": getattr(review, "review_id", "")})
        return Outcome(Verb.BLOCK, denial.get("policy_name") or "agntid-denied",
                       denial.get("reason") or getattr(result, "message", "denied"), details=details)

    async def _invoke_envelope(self, ctx: DelegationContext, name: str, args: dict[str, Any]) -> Outcome:
        agntid = self.agntid
        call_args = dict(args) | {self.task_argument: ctx.task_id}
        if ctx.delegation_id:
            call_args[self.delegation_argument] = ctx.delegation_id
        try:
            raw = await self._client.call_tool(name, call_args, raise_on_error=False)
        except Exception as exc:
            return Outcome(Verb.BLOCK, "agntid-error", f"runtime error: {type(exc).__name__}: {exc}"[:400],
                           details={"denial_step": "transport"})
        payload = _payload(raw)
        decision = agntid.parse_decision(payload) if payload else None
        flow = payload.get("__agntid_execution_flow") or {}
        if decision is not None and decision.waiting_for_review:
            review = decision.review
            return Outcome(Verb.ESCALATE, decision.policy_name or "review_required", decision.reason,
                           operation_id=getattr(review, "operation_id", "") or decision.correlation_id,
                           details={"status": "REVIEW_REQUIRED", "verdict_code": decision.code,
                                    "policy_name": decision.policy_name, "review_id": getattr(review, "review_id", "")})
        if getattr(raw, "is_error", False) or (decision is not None and decision.allowed is False):
            return Outcome(Verb.BLOCK, (decision and decision.policy_name) or "agntid-denied",
                           (decision and decision.reason) or str(_content(raw))[:300] or "denied",
                           details={"denial_step": flow.get("denial_step"),
                                    "policy_name": decision and decision.policy_name,
                                    "verdict_code": decision and decision.code,
                                    "intent_status": decision and decision.intent_status})
        return Outcome(Verb.ALLOW, (decision and decision.policy_name) or "agntid-allowed",
                       "allowed by the AgntID runtime", ToolResult(True, payload.get("__agntid_result", _content(raw))))

    def close_task(self, task_id: str) -> None:
        # Idempotent and never raises: the kill switch closes tasks the run may already have closed,
        # and a failed close must not lose the record of a finished run.
        if task_id in self._closed:
            return
        self._closed.add(task_id)
        for delegation_id in self._delegations.pop(task_id, []):
            try:
                self._run(self.agntid.send_delegation_close(self._client, task_id, delegation_id))
            except Exception:
                pass
        try:
            self._run(self.agntid.send_task_close(self._client, task_id))
        except Exception:
            pass


def _runtime_error(text: str) -> tuple[str, str] | None:
    """`{"error": ..., "code": ...}` embedded in a runtime-side failure message, if any."""
    start = text.find('{"error"')
    if start < 0:
        return None
    try:
        data = json.loads(text[start:text.rfind("}") + 1])
    except json.JSONDecodeError:
        return None
    return str(data.get("code") or "RUNTIME_ERROR"), str(data.get("error") or text)[:300]


def _name(tool: Any) -> str:
    return str((tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", "")) or "")


def _clean(result: Any) -> Any:
    if isinstance(result, dict):
        return dict(result)
    if hasattr(result, "value"):
        return result.value
    return _content(result)


def _content(result: Any) -> Any:
    structured = getattr(result, "structured_content", None) or getattr(result, "data", None)
    if structured:
        return structured
    blocks = getattr(result, "content", None) or []
    return "\n".join(getattr(b, "text", str(b)) for b in blocks) or result


def _payload(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        return result
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured.get("result", structured) if isinstance(structured.get("result"), dict) else structured
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", "")
        if "{" in text:
            try:
                return json.loads(text[text.find("{"):])
            except json.JSONDecodeError:
                continue
    return {}

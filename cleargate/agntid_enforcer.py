from __future__ import annotations

import asyncio
import json
import os
import threading
from typing import Any

from cleargate.enforcement import ApprovalEvidence, DelegationContext, Outcome, TaskOpen, delegation_id_for
from cleargate.events import Verb
from cleargate.policy import Policy
from cleargate.tools.base import ToolClient, ToolResult, ToolSpec

AGNTID_SOURCE = "agntid"

CONTROL_TOOLS = {"agntid_task_open", "agntid_task_close", "agntid_delegation_open",
                 "agntid_delegation_close", "agntid_action_update"}


class AgntIDNotWired(RuntimeError):
    pass


class AgntIDEnforcer:
    """Runs every gated call through the AgntID runtime (agntid-sdk 0.2.0, git main).

    Not exercised against a live runtime yet. The local stand-in remains the default
    until this class has been run against the hackathon runtime.
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
        self.tool_names: dict[str, str] = conf.get("tool_names", {})
        self.mcp_url = mcp_url or os.environ.get("AGNTID_MCP_URL", "http://localhost:8082/mcp")
        self.access_token = access_token or os.environ.get("AGNTID_ACCESS_TOKEN") or None
        self.review_shape = os.environ.get("AGNTID_REVIEW_SHAPE", "error")
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, daemon=True, name="agntid-loop").start()
        self._client = self._run(self._connect())
        self._users: dict[str, str] = {}

    def _run(self, coro: Any) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    async def _connect(self) -> Any:
        client = self.agntid.AgntidMCPClient(self.mcp_url, access_token=self.access_token)
        await client.__aenter__()
        return client

    def runtime_name(self, tool: str) -> str:
        return self.tool_names.get(tool, tool.split(".", 1)[-1])

    def open_task(self, user_id: str, prompt: str, tools: list[ToolSpec]) -> TaskOpen:
        agntid = self.agntid
        runtime_tools = self._run(agntid.get_tools_list(self._client))
        task_id = agntid.create_task(self.agent_id, user_id, prompt)
        self._users[task_id] = user_id
        opened = self._run(agntid.send_task_open_details(self._client, task_id, self.agent_id, user_id, prompt))
        shortlisted = agntid.filter_tools_for_task(runtime_tools, opened)
        relevant = {getattr(t, "name", None) or t.get("name") for t in shortlisted}
        visible = [t for t in tools if self.runtime_name(t.name) in relevant]
        business = [t for t in runtime_tools if (getattr(t, "name", None) or t.get("name")) not in CONTROL_TOOLS]
        snapshot = opened.snapshot
        return TaskOpen(
            task_id, visible,
            opened.eligible_tool_count if opened.eligible_tool_count is not None else len(business),
            opened.relevant_tool_count if opened.relevant_tool_count is not None else len(shortlisted),
            {"engine": "agntid", "snapshot_id": getattr(snapshot, "snapshot_id", ""),
             "constraints": list(getattr(snapshot, "constraints", ())),
             "relevant_tool_names": sorted(relevant)},
        )

    def open_delegation(self, parent: DelegationContext, agent: str, instruction: str) -> DelegationContext:
        agntid = self.agntid
        constraints = tuple(dict.fromkeys(parent.constraints + self.policy.constraints_for(agent)
                                          + tuple(agntid.extract_explicit_constraints(instruction))))
        delegation_id = delegation_id_for(parent.task_id, agent, instruction)
        allowlist = tuple(t for t in self.policy.visible_tools)
        context = agntid.DelegationContext(
            delegation_id=delegation_id,
            parent_agent_id=f"{self.agent_id}/{parent.agent}",
            acting_agent_id=f"{self.agent_id}/{agent}",
            delegated_intent=agntid.DelegatedIntent(text=instruction, constraints=constraints),
            parent_delegation_id=parent.delegation_id,
            tool_allowlist=tuple(self.runtime_name(t) for t in allowlist),
        )
        result = self._run(agntid.send_delegation_open(self._client, parent.task_id, context))
        payload = _payload(result)
        if payload.get("ok") is not True:
            raise AgntIDNotWired(f"agntid_delegation_open was not accepted: {payload}")
        return DelegationContext(parent.task_id, agent, parent.chain + (agent,), delegation_id,
                                 parent.delegation_id, constraints, instruction, allowlist)

    def invoke(self, ctx: DelegationContext, tool: str, args: dict[str, Any], inner: ToolClient,
               approval: ApprovalEvidence | None) -> Outcome:
        call_args = dict(args) | ({self.approval_argument: approval.to_dict()} if approval else {})
        if self.review_shape == "envelope":
            return self._run(self._invoke_envelope(ctx, self.runtime_name(tool), call_args))
        return self._run(self._invoke_wrapped(ctx, self.runtime_name(tool), call_args))

    async def _invoke_wrapped(self, ctx: DelegationContext, name: str, args: dict[str, Any]) -> Outcome:
        agntid = self.agntid
        wrapped = agntid.wrap_client(self._client, ctx.task_id, ctx.delegation_id or None,
                                     task_argument=self.task_argument, delegation_argument=self.delegation_argument)
        result = await wrapped.call_tool_async(name, args)
        if result:
            return Outcome(Verb.ALLOW, "agntid-allowed", "allowed by the AgntID runtime", ToolResult(True, _content(result)))
        denial = agntid.get_last_denial(clear=True) or {}
        review = denial.get("review")
        if denial.get("outcome") == "review_required":
            return Outcome(Verb.ESCALATE, denial.get("policy_name") or "review_required", denial.get("reason", ""),
                           operation_id=getattr(review, "operation_id", ""),
                           details={"status": "REVIEW_REQUIRED", "review_id": getattr(review, "review_id", ""),
                                    "verdict_code": denial.get("verdict_code")})
        return Outcome(Verb.BLOCK, denial.get("policy_name") or "agntid-denied",
                       denial.get("reason") or getattr(result, "message", "denied"),
                       details={k: denial[k] for k in ("intent_mismatch", "denial_step", "verdict_code", "outcome")
                                if denial.get(k)})

    async def _invoke_envelope(self, ctx: DelegationContext, name: str, args: dict[str, Any]) -> Outcome:
        agntid = self.agntid
        call_args = dict(args) | {self.task_argument: ctx.task_id}
        if ctx.delegation_id:
            call_args[self.delegation_argument] = ctx.delegation_id
        raw = await self._client.call_tool(name, call_args, raise_on_error=False)
        payload = _payload(raw)
        decision = agntid.parse_decision(payload)
        if decision.waiting_for_review:
            review = decision.review
            return Outcome(Verb.ESCALATE, decision.policy_name or "review_required", decision.reason,
                           operation_id=getattr(review, "operation_id", "") or decision.correlation_id,
                           details={"status": "REVIEW_REQUIRED", "verdict_code": decision.code,
                                    "review_id": getattr(review, "review_id", "")})
        if getattr(raw, "is_error", False) or decision.allowed is False:
            flow = payload.get("__agntid_execution_flow", {})
            return Outcome(Verb.BLOCK, decision.policy_name or "agntid-denied", decision.reason or "denied",
                           details={"denial_step": flow.get("denial_step"), "verdict_code": decision.code,
                                    "intent_status": decision.intent_status})
        return Outcome(Verb.ALLOW, decision.policy_name or "agntid-allowed", "allowed by the AgntID runtime",
                       ToolResult(True, payload.get("__agntid_result", _content(raw))))

    def close_task(self, task_id: str) -> None:
        self._run(self.agntid.send_task_close(self._client, task_id))


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
        return structured.get("result", structured)
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", "")
        if "{" in text:
            try:
                return json.loads(text[text.find("{"):])
            except json.JSONDecodeError:
                continue
    return {}

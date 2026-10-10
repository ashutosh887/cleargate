from __future__ import annotations

import json
from typing import Any

from cleargate.agents.brain import Brain
from cleargate.durable import Hibernate
from cleargate.tools.base import ToolClient, ToolResult, to_wire_name


class Agent:
    def __init__(self, name: str, system: str, brain: Brain, tools: ToolClient, max_steps: int = 12):
        self.name = name
        self.system = system
        self.brain = brain
        self.tools = tools
        self.max_steps = max_steps

    def run(self, instruction: str) -> str:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.system},
            {"role": "user", "content": instruction},
        ]
        return self.drive(messages, 0)

    def drive(self, messages: list[dict[str, Any]], start: int) -> str:
        for step in range(start, self.max_steps):
            turn = self.brain.next_turn(self.name, messages, self.tools.list_tools())
            if not turn.tool_calls:
                return turn.content
            messages.append({
                "role": "assistant",
                "content": turn.content or None,
                "tool_calls": [
                    {"id": c.id, "type": "function",
                     "function": {"name": to_wire_name(c.name), "arguments": json.dumps(c.args)}, **c.extra}
                    for c in turn.tool_calls
                ],
            })
            self._calls(messages, step, [(c.id, c.name, c.args) for c in turn.tool_calls])
        return f"{self.name} stopped after {self.max_steps} steps"

    def _calls(self, messages: list[dict[str, Any]], step: int, calls: list[tuple[str, str, dict[str, Any]]]) -> None:
        for index, (call_id, name, args) in enumerate(calls):
            try:
                result = self.tools.call(name, args)
            except Hibernate as sleep:
                sleep.agent = {"name": self.name, "messages": messages, "step": step,
                               "pending": [list(c) for c in calls[index:]]}
                raise
            self._answer(messages, call_id, result)

    @staticmethod
    def _answer(messages: list[dict[str, Any]], call_id: str, result: ToolResult) -> None:
        body = {"ok": result.ok, "content": result.content} if result.ok else {"ok": False, "error": result.error}
        messages.append({"role": "tool", "tool_call_id": call_id, "content": json.dumps(body, default=str)[:6000]})

    def finish_turn(self, checkpoint: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
        """Restore a hibernated loop: answer the held call and the rest of its turn, then return
        (messages, next step) for drive()."""
        messages = checkpoint["messages"]
        self._calls(messages, checkpoint["step"], [(c[0], c[1], c[2]) for c in checkpoint["pending"]])
        return messages, checkpoint["step"] + 1

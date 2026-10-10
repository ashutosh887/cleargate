from __future__ import annotations

import json
from typing import Any

from cleargate.agents.brain import Brain
from cleargate.tools.base import ToolClient, to_wire_name


class Agent:
    def __init__(self, name: str, system: str, brain: Brain, tools: ToolClient, max_steps: int = 10):
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
        for _ in range(self.max_steps):
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
            for call in turn.tool_calls:
                result = self.tools.call(call.name, call.args)
                body = {"ok": result.ok, "content": result.content} if result.ok else {"ok": False, "error": result.error}
                messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(body, default=str)[:6000]})
        return f"{self.name} stopped after {self.max_steps} steps"

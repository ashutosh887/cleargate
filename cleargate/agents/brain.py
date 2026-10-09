from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from cleargate.tools.base import ToolSpec, from_wire_name


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]
    id: str = field(default_factory=lambda: f"call_{uuid.uuid4().hex[:10]}")


@dataclass
class Turn:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


class Brain(Protocol):
    label: str

    def next_turn(self, agent: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> Turn: ...


class OpenAICompatibleBrain:
    def __init__(self, base_url: str, api_key: str, model: str):
        from openai import OpenAI

        self.client = OpenAI(base_url=base_url or None, api_key=api_key)
        self.model = model
        self.label = f"{model} via {base_url or 'api.openai.com'}"

    def next_turn(self, agent: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> Turn:
        response = self.client.chat.completions.create(
            model=self.model, messages=messages, tools=[t.to_openai() for t in tools] or None, temperature=0,
        )
        message = response.choices[0].message
        calls = []
        for call in message.tool_calls or []:
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"_unparsed": call.function.arguments}
            calls.append(ToolCall(from_wire_name(call.function.name), args, call.id))
        return Turn(message.content or "", calls)

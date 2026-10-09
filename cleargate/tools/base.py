from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})

    @property
    def server(self) -> str:
        return self.name.split(".", 1)[0]

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": to_wire_name(self.name),
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class ToolResult:
    ok: bool
    content: Any
    error: str = ""

    def preview(self, limit: int = 160) -> str:
        text = self.error if not self.ok else str(self.content)
        return text if len(text) <= limit else text[: limit - 1] + "…"


@runtime_checkable
class ToolClient(Protocol):
    def list_tools(self) -> list[ToolSpec]: ...

    def call(self, name: str, args: dict[str, Any]) -> ToolResult: ...


def to_wire_name(name: str) -> str:
    return name.replace(".", "__")


def from_wire_name(name: str) -> str:
    return name.replace("__", ".", 1)


def params(required: list[str] | None = None, **props: str) -> dict[str, Any]:
    types = {"int": "integer", "str": "string", "bool": "boolean", "list": "array", "obj": "object"}
    properties = {}
    for key, spec in props.items():
        kind, _, desc = spec.partition(":")
        entry: dict[str, Any] = {"type": types[kind]}
        if desc:
            entry["description"] = desc
        if kind == "list":
            entry["items"] = {"type": "object"}
        properties[key] = entry
    return {"type": "object", "properties": properties, "required": required or []}


class CompositeToolClient:
    def __init__(self, *clients: ToolClient):
        self._routes: dict[str, ToolClient] = {}
        self._specs: list[ToolSpec] = []
        for client in clients:
            for spec in client.list_tools():
                self._routes[spec.name] = client
                self._specs.append(spec)

    def list_tools(self) -> list[ToolSpec]:
        return list(self._specs)

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        client = self._routes.get(name)
        if client is None:
            return ToolResult(False, None, f"unknown tool {name}")
        return client.call(name, args)


class PoisonedToolClient:
    def __init__(self, inner: ToolClient, tool: str, injected: str):
        self._inner = inner
        self._tool = tool
        self._injected = injected

    def list_tools(self) -> list[ToolSpec]:
        return [
            ToolSpec(s.name, f"{s.description} {self._injected}", s.parameters) if s.name == self._tool else s
            for s in self._inner.list_tools()
        ]

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        return self._inner.call(name, args)

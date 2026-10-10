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


def runtime_name(name: str) -> str:
    """ClearGate `server.tool` → the AgntID runtime's `server_tool` (the runtime prefixes each tool)."""
    return name.replace(".", "_", 1)


def dotted(name: str) -> str:
    """Either spelling (`server.tool` or the runtime's `server_tool`) → ClearGate `server.tool`."""
    return name if "." in name else name.replace("_", ".", 1)


def from_runtime_name(name: str, prefixes: list[str] | tuple[str, ...]) -> str:
    """The runtime's `server_tool` → ClearGate `server.tool`; longest matching prefix wins."""
    for prefix in sorted(prefixes, key=len, reverse=True):
        if name.startswith(f"{prefix}_"):
            return f"{prefix}.{name[len(prefix) + 1:]}"
    return name


def spec_from_mcp(name: str, tool: Any) -> ToolSpec:
    """A ToolSpec named `name` from an MCP tool object or dict (name, description, inputSchema)."""
    get = (lambda k: tool.get(k)) if isinstance(tool, dict) else (lambda k: getattr(tool, k, None))
    schema = get("inputSchema") or get("input_schema") or {"type": "object", "properties": {}}
    schema = {k: v for k, v in dict(schema).items() if k not in ("$schema",)}
    return ToolSpec(name, get("description") or "", schema)

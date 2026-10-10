from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from cleargate.tools.base import ToolSpec, from_wire_name, to_wire_name


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]
    id: str = field(default_factory=lambda: f"call_{uuid.uuid4().hex[:10]}")
    extra: dict[str, Any] = field(default_factory=dict)  # provider fields to echo back (Gemini thought_signature)


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
            extra = {k: v for k, v in (getattr(call, "model_extra", None) or {}).items() if k == "extra_content"}
            calls.append(ToolCall(from_wire_name(call.function.name), args, call.id, extra))
        return Turn(message.content or "", calls)


# --- Amazon Bedrock (Converse API) with model fallback and an Anthropic API last resort ------------------

_RETRYABLE = {"ThrottlingException", "ServiceUnavailableException", "ModelNotReadyException",
              "ServiceQuotaExceededException", "ModelTimeoutException", "InternalServerException",
              "AccessDeniedException", "ResourceNotFoundException", "ModelErrorException"}


def _openai_to_converse(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Translate the loop's OpenAI-style transcript into Converse (system, messages)."""
    system: list[dict[str, Any]] = []
    out: list[dict[str, Any]] = []
    for m in messages:
        role = m.get("role")
        if role == "system":
            system.append({"text": m["content"]})
        elif role == "user":
            out.append({"role": "user", "content": [{"text": m["content"] or "(empty)"}]})
        elif role == "assistant":
            blocks: list[dict[str, Any]] = [{"text": m["content"]}] if m.get("content") else []
            for c in m.get("tool_calls") or []:
                try:
                    args = json.loads(c["function"]["arguments"] or "{}")
                except json.JSONDecodeError:
                    args = {}
                blocks.append({"toolUse": {"toolUseId": c["id"], "name": c["function"]["name"], "input": args}})
            out.append({"role": "assistant", "content": blocks or [{"text": "(no content)"}]})
        elif role == "tool":
            try:
                ok = bool(json.loads(m["content"]).get("ok", True))
            except (json.JSONDecodeError, AttributeError):
                ok = True
            block = {"toolResult": {"toolUseId": m["tool_call_id"], "content": [{"text": m["content"]}],
                                    "status": "success" if ok else "error"}}
            if out and out[-1]["role"] == "user" and all("toolResult" in b for b in out[-1]["content"]):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
    return system, out


def _openai_to_anthropic(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    system, converse = _openai_to_converse(messages)
    out: list[dict[str, Any]] = []
    for m in converse:
        blocks = []
        for b in m["content"]:
            if "text" in b:
                blocks.append({"type": "text", "text": b["text"]})
            elif "toolUse" in b:
                u = b["toolUse"]
                blocks.append({"type": "tool_use", "id": u["toolUseId"], "name": u["name"], "input": u["input"]})
            elif "toolResult" in b:
                r = b["toolResult"]
                blocks.append({"type": "tool_result", "tool_use_id": r["toolUseId"], "content": r["content"][0]["text"],
                               "is_error": r["status"] == "error"})
        out.append({"role": m["role"], "content": blocks})
    return "\n\n".join(s["text"] for s in system), out


class BedrockBrain:
    """Claude on Amazon Bedrock via the Converse API. Auth: AWS_BEARER_TOKEN_BEDROCK (read by boto3 itself)
    or the normal AWS credential chain. On throttling it falls back to a second model, then to the Anthropic
    API (ANTHROPIC_API_KEY) if one is configured."""

    def __init__(self, region: str, model: str, fallback_model: str = "", anthropic_api_key: str = "",
                 anthropic_model: str = "claude-sonnet-5-5", max_tokens: int = 1024):
        import boto3
        from botocore.config import Config

        self.region = region
        self.models = [m for m in (model, fallback_model) if m]
        self.anthropic_api_key = anthropic_api_key
        self.anthropic_model = anthropic_model
        self.max_tokens = max_tokens
        self.client = boto3.client("bedrock-runtime", region_name=region, config=Config(
            retries={"max_attempts": 2, "mode": "standard"}, read_timeout=90, connect_timeout=10))
        self._anthropic = None
        self.last_model = self.models[0] if self.models else anthropic_model
        self.label = f"{self.last_model} via Amazon Bedrock ({region})"

    def next_turn(self, agent: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> Turn:
        from botocore.exceptions import ClientError, NoCredentialsError

        system, converse = _openai_to_converse(messages)
        request: dict[str, Any] = {"messages": converse, "system": system,
                                   "inferenceConfig": {"maxTokens": self.max_tokens, "temperature": 0}}
        if tools:
            request["toolConfig"] = {"tools": [{"toolSpec": {
                "name": to_wire_name(t.name)[:64], "description": t.description or t.name,
                "inputSchema": {"json": t.parameters}}} for t in tools]}
        last_error: Exception | None = None
        for model in self.models:
            try:
                response = self.client.converse(modelId=model, **request)
            except ClientError as exc:
                last_error = exc
                if exc.response.get("Error", {}).get("Code") in _RETRYABLE:
                    continue
                raise
            except NoCredentialsError as exc:
                last_error = exc
                break
            self._note(model, "Amazon Bedrock")
            calls, text = [], []
            for block in response["output"]["message"]["content"]:
                if "text" in block:
                    text.append(block["text"])
                elif "toolUse" in block:
                    u = block["toolUse"]
                    calls.append(ToolCall(from_wire_name(u["name"]), u.get("input") or {}, u["toolUseId"]))
            return Turn("\n".join(text), calls)
        if self.anthropic_api_key:
            return self._anthropic_turn(messages, tools)
        raise RuntimeError(f"Bedrock unavailable and no ANTHROPIC_API_KEY fallback: {last_error}")

    def _note(self, model: str, via: str) -> None:
        if model != self.last_model:
            self.last_model = model
            self.label = f"{model} via {via}" + (f" ({self.region})" if via == "Amazon Bedrock" else "")

    def _anthropic_turn(self, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> Turn:
        if self._anthropic is None:
            from anthropic import Anthropic

            self._anthropic = Anthropic(api_key=self.anthropic_api_key)
        system, converted = _openai_to_anthropic(messages)
        kwargs: dict[str, Any] = {"model": self.anthropic_model, "max_tokens": self.max_tokens,
                                  "system": system, "messages": converted}
        if tools:
            kwargs["tools"] = [{"name": to_wire_name(t.name)[:64], "description": t.description or t.name,
                                "input_schema": t.parameters} for t in tools]
        response = self._anthropic.messages.create(**kwargs)
        self._note(self.anthropic_model, "Anthropic API")
        calls = [ToolCall(from_wire_name(b.name), dict(b.input or {}), b.id) for b in response.content
                 if b.type == "tool_use"]
        text = "\n".join(b.text for b in response.content if b.type == "text")
        return Turn(text, calls)


class AnthropicBrain(BedrockBrain):
    """Anthropic API only (no Bedrock)."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-5-5", max_tokens: int = 1024):
        self.region = ""
        self.models = []
        self.anthropic_api_key = api_key
        self.anthropic_model = model
        self.max_tokens = max_tokens
        self._anthropic = None
        self.last_model = model
        self.label = f"{model} via Anthropic API"

    def next_turn(self, agent: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> Turn:
        return self._anthropic_turn(messages, tools)

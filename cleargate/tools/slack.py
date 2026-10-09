from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx

from cleargate.tools.base import ToolResult, ToolSpec, params

SPECS = [
    ToolSpec("slack.slack_post_message", "Post a message to a Slack channel.", params(["channel", "text"], channel="str", text="str")),
    ToolSpec("slack.slack_list_channels", "List Slack channels the bot can see.", params()),
]


class SlackLive:
    def __init__(self, bot_token: str = "", webhook_url: str = ""):
        self.bot_token = bot_token
        self.webhook_url = webhook_url
        self.http = httpx.Client(timeout=15)

    def list_tools(self) -> list[ToolSpec]:
        return list(SPECS)

    def post(self, channel: str, text: str, blocks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"channel": channel, "text": text} | ({"blocks": blocks} if blocks else {})
        if self.bot_token:
            response = self.http.post("https://slack.com/api/chat.postMessage", json=payload,
                                      headers={"Authorization": f"Bearer {self.bot_token}"})
            data = response.json()
            if not data.get("ok"):
                raise RuntimeError(data.get("error", "slack error"))
            return {"channel": data["channel"], "ts": data["ts"]}
        response = self.http.post(self.webhook_url, json={k: v for k, v in payload.items() if k != "channel"})
        response.raise_for_status()
        return {"channel": channel, "ts": None, "via": "webhook"}

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        try:
            if name == "slack.slack_post_message":
                return ToolResult(True, self.post(args["channel"], args["text"]))
            if name == "slack.slack_list_channels" and self.bot_token:
                response = self.http.get("https://slack.com/api/conversations.list",
                                         headers={"Authorization": f"Bearer {self.bot_token}"})
                return ToolResult(True, [f"#{c['name']}" for c in response.json().get("channels", [])])
            return ToolResult(False, None, f"{name} needs a bot token")
        except (httpx.HTTPError, RuntimeError, KeyError) as exc:
            return ToolResult(False, None, f"{type(exc).__name__}: {exc}")


class SlackStub:
    CHANNELS = ["#inc-4471", "#eng-payments", "#general", "#finance"]

    def __init__(self, workdir: Path):
        self.outbox = workdir / "slack_outbox.jsonl"
        self.outbox.unlink(missing_ok=True)
        self._lock = threading.Lock()

    def list_tools(self) -> list[ToolSpec]:
        return list(SPECS)

    def post(self, channel: str, text: str, blocks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        entry = {"channel": channel, "text": text, "blocks": blocks, "ts": f"{time.time():.6f}"}
        with self._lock, self.outbox.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")
        return {"channel": channel, "ts": entry["ts"], "via": "stub outbox"}

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        if name == "slack.slack_list_channels":
            return ToolResult(True, self.CHANNELS)
        try:
            return ToolResult(True, self.post(args["channel"], args["text"]))
        except KeyError as exc:
            return ToolResult(False, None, f"missing argument {exc}")

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx


class SlackLive:
    def __init__(self, bot_token: str = "", webhook_url: str = ""):
        self.bot_token = bot_token
        self.webhook_url = webhook_url
        self.http = httpx.Client(timeout=15)

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


class SlackStub:
    def __init__(self, workdir: Path, fresh: bool = True):
        workdir.mkdir(parents=True, exist_ok=True)
        self.outbox = workdir / "slack_outbox.jsonl"
        if fresh:
            self.outbox.unlink(missing_ok=True)
        self._lock = threading.Lock()

    def post(self, channel: str, text: str, blocks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        entry = {"channel": channel, "text": text, "blocks": blocks, "ts": f"{time.time():.6f}"}
        with self._lock, self.outbox.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")
        return {"channel": channel, "ts": entry["ts"], "via": "stub outbox"}

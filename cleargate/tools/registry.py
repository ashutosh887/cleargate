from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cleargate.config import Settings
from cleargate.tools.base import CompositeToolClient, ToolClient, ToolResult, ToolSpec, params, spec_from_mcp
from cleargate.tools.github import GitHubRest, GitHubStub, SandboxGitHub
from cleargate.tools.postgres import PostgresLive, PostgresStub
from cleargate.tools.slack import SlackLive, SlackStub

INCIDENT_CHANNEL = "#inc-4471"

DEFAULT_MCP_URLS = {
    "payments": "http://localhost:9101/mcp",
    "comms": "http://localhost:9102/mcp",
    "github": "https://api.githubcopilot.com/mcp/",
}

PAYMENTS_SPECS = [
    ToolSpec("payments.query_refunds", "List refunds for an order (or all orders when order_id is empty), newest first.",
             params(["order_id", "limit"], order_id="str", limit="int:rows to return, 1-100")),
    ToolSpec("payments.get_order", "Get one order by id.", params(["order_id"], order_id="str")),
    ToolSpec("payments.issue_refund", "Issue a refund for an order, in whole rupees.",
             params(["order_id", "amount_inr"], order_id="str", amount_inr="int")),
    ToolSpec("payments.export_customer_records", "Export customer records (name, email, phone, masked card) for a segment.",
             params(["segment"], segment="str")),
    ToolSpec("payments.run_sql", "Run raw SQL against the payments database.", params(["sql"], sql="str")),
]

COMMS_SPECS = [
    ToolSpec("comms.post_incident_update", f"Post an update to the incident channel {INCIDENT_CHANNEL}.",
             params(["text"], text="str")),
    ToolSpec("comms.post_message", "Post a message to any Slack channel.", params(["channel", "text"], channel="str", text="str")),
    ToolSpec("comms.send_email", "Send an email.", params(["to", "subject", "body"], to="str", subject="str", body="str")),
]


class PaymentsLocal:
    """In-process stand-in for the payments MCP server (same tool names and params)."""

    def __init__(self, db: PostgresStub | PostgresLive):
        self.db = db

    def list_tools(self) -> list[ToolSpec]:
        return list(PAYMENTS_SPECS)

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        try:
            tool = name.removeprefix("payments.")
            if tool == "query_refunds":
                limit = max(1, min(int(args.get("limit") or 50), 1000))
                order = str(args.get("order_id") or "").strip()
                where, bind = ("WHERE order_id = %s", (order,)) if order and order != "*" else ("", ())
                return ToolResult(True, self.db.query(
                    "SELECT id, order_id, charge_id, requested, amount_inr, refunded_minor, expected_minor, "
                    f"idempotency_key, status, created_at FROM payments.refunds {where} ORDER BY id", bind, limit))
            if tool == "get_order":
                rows = self.db.query("SELECT * FROM payments.orders WHERE order_id = %s", (str(args["order_id"]),), 1)
                return ToolResult(bool(rows), rows[0] if rows else None, "" if rows else "no such order")
            if tool == "issue_refund":
                order, amount = str(args["order_id"]), int(args["amount_inr"])
                key = f"rf_{order}_{uuid.uuid4().hex[:12]}"
                self.db.query("INSERT INTO payments.refunds (order_id, charge_id, requested, amount_inr, refunded_minor, "
                              "expected_minor, idempotency_key, status, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                              (order, "ch_agent", f"{amount}.00", amount, amount * 100, amount * 100, key, "ok",
                               time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
                return ToolResult(True, {"order_id": order, "amount_inr": amount, "idempotency_key": key})
            if tool == "export_customer_records":
                segment = str(args.get("segment") or "")
                where, bind = ("WHERE segment = %s", (segment,)) if segment and segment != "all" else ("", ())
                return ToolResult(True, self.db.query(f"SELECT * FROM customers.cards {where}", bind, 1000))
            if tool == "run_sql":
                return ToolResult(True, self.db.query(str(args["sql"])))
            return ToolResult(False, None, f"unknown tool {name}")
        except Exception as exc:
            return ToolResult(False, None, f"{type(exc).__name__}: {exc}")


class CommsLocal:
    """In-process stand-in for the comms MCP server. Email always goes to a stub outbox."""

    def __init__(self, slack: SlackStub | SlackLive, workdir: Path):
        self.slack = slack
        self.email_outbox = workdir / "email_outbox.jsonl"
        self.email_outbox.unlink(missing_ok=True)
        self._lock = threading.Lock()

    def list_tools(self) -> list[ToolSpec]:
        return list(COMMS_SPECS)

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        try:
            tool = name.removeprefix("comms.")
            if tool == "post_incident_update":
                return ToolResult(True, self.slack.post(INCIDENT_CHANNEL, str(args["text"])))
            if tool == "post_message":
                return ToolResult(True, self.slack.post(str(args["channel"]), str(args["text"])))
            if tool == "send_email":
                entry = {k: str(args.get(k, "")) for k in ("to", "subject", "body")} | {"ts": time.time()}
                with self._lock, self.email_outbox.open("a") as fh:
                    fh.write(json.dumps(entry) + "\n")
                return ToolResult(True, {"to": entry["to"], "status": "queued (stub outbox, never sent)"})
            return ToolResult(False, None, f"unknown tool {name}")
        except Exception as exc:
            return ToolResult(False, None, f"{type(exc).__name__}: {exc}")


class McpToolClient:
    """Direct (stock) connection to MCP servers, one per prefix. Tool names come back as
    `prefix.tool`, so they line up with the runtime's `prefix_tool` names one-to-one.
    A server that cannot be reached contributes no tools; see `.errors`."""

    def __init__(self, servers: dict[str, tuple[str, str | None, dict[str, str]]], timeout: float = 30.0):
        self.timeout = timeout
        self.errors: dict[str, str] = {}
        self._clients: dict[str, Any] = {}
        self._specs: list[ToolSpec] = []
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, daemon=True, name="mcp-direct").start()
        for prefix, (url, token, headers) in servers.items():
            try:
                self._run(self._connect(prefix, url, token, headers))
            except Exception as exc:
                self.errors[prefix] = f"{type(exc).__name__}: {exc}"

    def _run(self, coro: Any) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(self.timeout)

    async def _connect(self, prefix: str, url: str, token: str | None, headers: dict[str, str]) -> None:
        from fastmcp import Client
        from fastmcp.client.transports import StreamableHttpTransport

        client = Client(StreamableHttpTransport(url, headers=headers or None, auth=token or None))
        await client.__aenter__()
        tools = await client.list_tools()
        self._clients[prefix] = client
        self._specs.extend(spec_from_mcp(f"{prefix}.{t.name}", t) for t in tools)

    def list_tools(self) -> list[ToolSpec]:
        return list(self._specs)

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        prefix, _, tool = name.partition(".")
        client = self._clients.get(prefix)
        if client is None:
            return ToolResult(False, None, f"MCP server {prefix!r} is not connected: {self.errors.get(prefix, 'unknown')}")
        try:
            result = self._run(client.call_tool(tool, args, raise_on_error=False))
        except Exception as exc:
            return ToolResult(False, None, f"{type(exc).__name__}: {exc}")
        content = mcp_content(result)
        return ToolResult(not getattr(result, "is_error", False), content,
                          str(content)[:500] if getattr(result, "is_error", False) else "")


def mcp_content(result: Any) -> Any:
    """Plain content of an MCP tool result: structured content, else joined text (JSON-decoded if it is JSON)."""
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict) and structured:
        return structured["result"] if set(structured) == {"result"} else structured
    texts = [getattr(b, "text", None) for b in getattr(result, "content", None) or []]
    text = "\n".join(t for t in texts if t)
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return text


@dataclass
class ToolBackends:
    client: ToolClient
    # verifies outcomes on GitHub (stub repo or REST); None without a token
    github: GitHubStub | GitHubRest | None
    postgres: PostgresStub | PostgresLive | None
    slack: SlackStub | SlackLive | None
    labels: dict[str, str]
    kind: str = "local"
    sandbox: SandboxGitHub | None = None


def tools_mode(force_stub: bool = False) -> str:
    """`local` (in-process stand-ins, the default) or `mcp` (real MCP servers, CLEARGATE_TOOLS=mcp)."""
    return "local" if force_stub else (os.environ.get("CLEARGATE_TOOLS", "local").strip().lower() or "local")


def _sandboxed(backends: ToolBackends, base_branch: str, settings: Settings) -> ToolBackends:
    if isinstance(backends.github, GitHubStub) or settings.github == "stub":
        return backends
    rest = backends.github if isinstance(backends.github, GitHubRest) else (
        GitHubRest(settings.github_token, settings.github_repo) if settings.github_token and settings.github_repo else None)
    if isinstance(backends.github, GitHubRest):
        backends.github.base_branch = base_branch
    backends.sandbox = SandboxGitHub(backends.client, base_branch, rest.pr_base if rest else None)
    backends.client = backends.sandbox
    backends.labels["github"] += f" [sandbox base: {base_branch}]"
    return backends


def build_tools(settings: Settings, workdir: Path, force_stub: bool = False, base_branch: str = "main") -> ToolBackends:
    """`base_branch` is the scenario's "main": "main" for the stub, `demo/<mode>-<run_id>` on a live run."""
    workdir.mkdir(parents=True, exist_ok=True)
    if tools_mode(force_stub) == "mcp":
        return _sandboxed(_build_mcp(settings, workdir), base_branch, settings)
    live = not force_stub
    github = (GitHubRest(settings.github_token, settings.github_repo)
              if live and settings.github == "live" else GitHubStub(workdir))
    postgres = (PostgresLive(settings.database_url)
                if live and settings.postgres == "live" else PostgresStub(workdir))
    slack = (SlackLive(settings.slack_bot_token, settings.slack_webhook_url)
             if live and settings.slack == "live" else SlackStub(workdir))
    labels = {
        "github": "GitHub REST" if isinstance(github, GitHubRest) else "local git repo (stub)",
        "payments": "in-process over Postgres" if isinstance(postgres, PostgresLive) else "in-process over SQLite (stub)",
        "comms": ("Slack" if isinstance(slack, SlackLive) else "JSONL outbox (stub)") + "; email: stub outbox",
    }
    client = CompositeToolClient(github, PaymentsLocal(postgres), CommsLocal(slack, workdir))
    return _sandboxed(ToolBackends(client, github, postgres, slack, labels, "local"), base_branch, settings)


def _build_mcp(settings: Settings, workdir: Path) -> ToolBackends:
    env = os.environ.get
    servers: dict[str, tuple[str, str | None, dict[str, str]]] = {
        "payments": (env("CLEARGATE_PAYMENTS_MCP_URL") or DEFAULT_MCP_URLS["payments"], None, {}),
        "comms": (env("CLEARGATE_COMMS_MCP_URL") or DEFAULT_MCP_URLS["comms"], None, {}),
    }
    clients: list[ToolClient] = []
    verify: GitHubStub | GitHubRest | None = None
    if settings.github == "stub":
        verify = GitHubStub(workdir)
        clients.append(verify)
        github_label = "local git repo (stub)"
    elif settings.github == "rest":
        verify = GitHubRest(settings.github_token, settings.github_repo)
        clients.append(verify)
        github_label = "GitHub REST (agent holds the PAT)"
    else:
        url = env("CLEARGATE_GITHUB_MCP_URL") or DEFAULT_MCP_URLS["github"]
        toolsets = env("CLEARGATE_GITHUB_TOOLSETS") or "context,repos,issues,pull_requests,actions"
        servers["github"] = (url, settings.github_token or None, {"X-MCP-Toolsets": toolsets})
        verify = GitHubRest(settings.github_token, settings.github_repo) if settings.github_token and settings.github_repo else None
        github_label = f"GitHub MCP {url} (agent holds the PAT)"
    direct = McpToolClient(servers)
    labels = {p: f"MCP {u}" + (f" UNREACHABLE: {direct.errors[p]}" if p in direct.errors else "")
              for p, (u, _, _) in servers.items() if p != "github"}
    labels["github"] = github_label + (f" UNREACHABLE: {direct.errors['github']}" if "github" in direct.errors else "")
    client = CompositeToolClient(*clients, direct) if clients else direct
    return ToolBackends(client, verify, None, None, labels, "mcp")

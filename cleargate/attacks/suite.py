"""Attack suite runner.

    python -m cleargate.attacks.suite [--target stock|agntid|both] [--out records/attacks-<ts>.json]

Fires the catalog in attacks/catalog.yaml at the ClearGate tools, two ways:

* **stock**: call the MCP servers directly (payments :9101, comms :9102, github
  :9103, else the official GitHub remote MCP with GITHUB_TOKEN). "reached a tool"
  means the call executed without an MCP error, i.e. no control stopped it.
  Attacks marked `destructive` on GitHub (merge, push to main) are never executed
  in stock mode: they are reported "simulated" (tool present, nothing in the way).
* **agntid**: connect through the agntid SDK to the runtime, open the real
  incident task, and classify each attack as hidden / denied / allowed. If the
  runtime has not discovered any business tools yet, this target reports
  "runtime not ready" cleanly and the stock path still runs.

Mutating attacks target stub-safe values; the DB is reseeded after the stock run
regardless. Email is a stub outbox and is never really sent. A destructive attack
whose owner/repo is GITHUB_REPO is never sent on either path.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import warnings
from pathlib import Path
from typing import Any

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*authlib.jose.*")

import yaml

from cleargate.canonical import arguments_digest
from cleargate.agntid_enforcer import CONTROL_TOOLS as AGNTID_CONTROL_TOOLS
from cleargate.config import ROOT, Settings

CATALOG = ROOT / "attacks" / "catalog.yaml"

STOCK_ENDPOINTS = {
    "payments": "http://localhost:9101/mcp",
    "comms": "http://localhost:9102/mcp",
    "github": "http://localhost:9103/mcp",
}
GITHUB_REMOTE_MCP = "https://api.githubcopilot.com/mcp/"


def load_catalog() -> dict[str, Any]:
    return yaml.safe_load(CATALOG.read_text())


def server_of(tool: str) -> str:
    return tool.split("_", 1)[0]


def bare_tool(tool: str) -> str:
    return tool.split("_", 1)[1]


def targets_own_repo(atk: dict[str, Any]) -> bool:
    """True for a destructive GitHub attack aimed at the real repo (GITHUB_REPO); those are never sent."""
    repo = Settings().github_repo
    args = atk.get("args") or {}
    return bool(atk.get("destructive") and repo and f"{args.get('owner')}/{args.get('repo')}" == repo)



async def run_stock(attacks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    results: list[dict[str, Any]] = []
    clients: dict[str, Any] = {}
    available: dict[str, list[str]] = {}
    endpoint: dict[str, str] = {}

    async def client_for(server: str) -> Any | None:
        if server in clients:
            return clients[server]
        if server not in STOCK_ENDPOINTS:
            clients[server] = None
            return None
        endpoints: list[tuple[str, dict[str, str]]] = [(STOCK_ENDPOINTS[server], {})]
        token = Settings().github_token
        if server == "github" and token:
            endpoints.append((GITHUB_REMOTE_MCP, {"Authorization": f"Bearer {token}"}))
        clients[server] = None
        available[server] = []
        for url, headers in endpoints:
            try:
                c = Client(StreamableHttpTransport(url, headers=headers or None))
                await c.__aenter__()
                available[server] = [t.name for t in await c.list_tools()]
                clients[server] = c
                endpoint[server] = url
                break
            except Exception as exc:
                print(f"[stock] {server} at {url} unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
        return clients[server]

    for atk in attacks:
        tool = atk["tool"]
        server, name = server_of(tool), bare_tool(tool)
        row = _row(atk)
        c = await client_for(server)
        if c is None:
            row |= {"outcome": "server-down", "reached_tool": False,
                    "detail": f"{server} MCP server not reachable"}
            results.append(row)
            continue
        if name not in available.get(server, []):
            row |= {"outcome": "tool-absent", "reached_tool": False,
                    "detail": f"no tool {name} on {server}"}
            results.append(row)
            continue
        if server == "github" and atk.get("destructive"):
            row |= {"outcome": "simulated", "reached_tool": False,
                    "detail": f"simulated (not executed against the real repo): {name} is exposed by "
                              f"{endpoint[server]} and nothing on the stock path would stop it"}
            results.append(row)
            continue
        try:
            res = await c.call_tool(name, atk["args"], raise_on_error=True)
            row |= {"outcome": "reached", "reached_tool": True,
                    "detail": _summarize(res)}
        except Exception as exc:
            # The server rejected the args (e.g. negative amount), but the call reached the tool.
            row |= {"outcome": "tool-error", "reached_tool": True,
                    "detail": f"{type(exc).__name__}: {str(exc)[:160]}"}
        results.append(row)

    for c in clients.values():
        if c is not None:
            try:
                await c.__aexit__(None, None, None)
            except Exception:
                pass
    return results


def _summarize(res: Any) -> str:
    sc = getattr(res, "structured_content", None)
    if isinstance(sc, dict):
        for k in ("count", "status", "rows_affected", "rows", "order_id"):
            if k in sc:
                return f"{k}={sc[k]}"
        return ",".join(list(sc)[:4])
    return "ok"



async def run_agntid(attacks: list[dict[str, Any]], prompt: str) -> dict[str, Any]:
    try:
        import agntid
    except ImportError as exc:
        return {"status": "runtime not ready", "reason": f"agntid SDK not installed: {exc}", "results": []}

    import os
    mcp_url = os.environ.get("AGNTID_MCP_URL", "http://localhost:8082/mcp")
    token = os.environ.get("AGNTID_ACCESS_TOKEN") or None
    agent_id, user_id = "cleargate:attacks", "oncall-1"

    try:
        client = agntid.AgntidMCPClient(mcp_url, access_token=token)
        await client.__aenter__()
    except Exception as exc:
        return {"status": "runtime not ready", "reason": f"cannot connect to {mcp_url}: {type(exc).__name__}: {exc}",
                "results": []}

    try:
        try:
            tools = await agntid.get_tools_list(client)
        except Exception as exc:
            return {"status": "runtime not ready", "reason": f"list_tools failed: {type(exc).__name__}: {exc}",
                    "results": []}
        names = [(getattr(t, "name", None) or (t.get("name") if isinstance(t, dict) else None)) for t in (tools or [])]
        business = [n for n in names if n and n not in AGNTID_CONTROL_TOOLS]
        if not business:
            return {"status": "runtime not ready",
                    "reason": "runtime exposes no business tools yet (not discovered / no MCP servers attached)",
                    "visible_tools": names, "results": []}
        # A runtime showing only built-in demo_* tools has not attached the ClearGate servers yet.
        cleargate_prefixes = {server_of(a["tool"]) for a in attacks}
        if not any(server_of(n) in cleargate_prefixes for n in business):
            return {"status": "runtime not ready",
                    "reason": ("ClearGate MCP servers (payments/comms/github) not attached to the runtime yet; "
                               f"only these tools are discovered: {sorted(business)}"),
                    "visible_tools": sorted(business), "results": []}

        visible = set(business)
        task_id = agntid.create_task(agent_id, user_id, prompt)
        wrapped = agntid.wrap_client(client, task_id)
        results: list[dict[str, Any]] = []
        async with agntid.task_context(client, task_id):
            try:
                opened = await agntid.send_task_open_details(client, task_id, agent_id, user_id, prompt)
            except Exception as exc:
                return {"status": "runtime not ready", "reason": f"task open failed: {type(exc).__name__}: {exc}",
                        "visible_tools": names, "results": []}
            if not getattr(opened, "ok", False):
                return {"status": "runtime not ready",
                        "reason": f"task open rejected: {getattr(opened, 'reason', '')}",
                        "visible_tools": names, "results": []}
            try:
                shortlisted = agntid.filter_tools_for_task(tools, opened)
            except agntid.IntentPreparationError as exc:
                return {"status": "runtime not ready", "reason": f"intent preparation failed: {exc}",
                        "visible_tools": names, "results": []}
            shortlist_names = {getattr(t, "name", None) or (t.get("name") if isinstance(t, dict) else None)
                               for t in shortlisted}

            for atk in attacks:
                tool = atk["tool"]
                row = _row(atk)
                if targets_own_repo(atk):
                    row |= {"outcome": "skipped", "detail": "destructive attack on GITHUB_REPO; never sent"}
                    results.append(row)
                    continue
                if tool not in visible:
                    row |= {"outcome": "hidden", "detail": "tool not visible under profile/intent"}
                    results.append(row)
                    continue
                try:
                    res = await wrapped.call_tool_async(tool, atk["args"])
                except Exception as exc:
                    row |= {"outcome": "error", "detail": f"{type(exc).__name__}: {str(exc)[:160]}"}
                    results.append(row)
                    continue
                if res and not getattr(res, "denied", False):
                    row |= {"outcome": "allowed", "detail": _summarize(res)}
                else:
                    denial = agntid.get_last_denial(clear=True) or {}
                    row |= {"outcome": "denied",
                            "reason": denial.get("reason", getattr(res, "message", "")),
                            "policy_name": denial.get("policy_name", ""),
                            "denial_step": denial.get("denial_step", ""),
                            "intent_mismatch": denial.get("intent_mismatch", ""),
                            "verdict_code": denial.get("verdict_code", "")}
                results.append(row)

        return {"status": "ready", "visible_tools": sorted(business),
                "shortlisted_tools": sorted(n for n in shortlist_names if n),
                "eligible_tool_count": opened.eligible_tool_count,
                "relevant_tool_count": opened.relevant_tool_count,
                "results": results}
    finally:
        try:
            await client.__aexit__(None, None, None)
        except Exception:
            pass



def _row(atk: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": atk["id"],
        "owasp": atk["owasp"],
        "klass": atk["klass"],
        "tool": atk["tool"],
        "args_digest": arguments_digest(atk["args"]),
        "expected_control": atk["expected_control"],
    }


def reseed() -> None:
    try:
        from cleargate.mcp import seed
        counts = seed.apply()
        print(f"[reseed] restored DB: {counts}", file=sys.stderr)
    except Exception as exc:
        print(f"[reseed] WARNING: reseed failed: {type(exc).__name__}: {exc}", file=sys.stderr)


def print_table(title: str, rows: list[dict[str, Any]]) -> None:
    print(f"\n== {title} ==")
    print(f"{'id':<30} {'owasp':<6} {'expect':<11} {'outcome':<12} detail")
    print("-" * 100)
    for r in rows:
        detail = r.get("detail") or r.get("reason") or ""
        print(f"{r['id']:<30} {r['owasp']:<6} {r['expected_control']:<11} {r['outcome']:<12} {str(detail)[:40]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cleargate.attacks.suite", description=__doc__)
    parser.add_argument("--target", choices=["stock", "agntid", "both"], default="both")
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)

    catalog = load_catalog()
    attacks = catalog["attacks"]
    prompt = catalog["task_prompt"].strip()
    ts = time.strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else ROOT / "records" / f"attacks-{ts}.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {"ts": ts, "prompt": prompt, "attack_count": len(attacks)}

    stock_counts = agntid_summary = None
    if args.target in ("stock", "both"):
        stock_rows = asyncio.run(run_stock(attacks))
        report["stock"] = stock_rows
        print_table("STOCK (direct MCP, no runtime)", stock_rows)
        stock_counts = {"reached": sum(1 for r in stock_rows if r.get("reached_tool")),
                        "simulated": sum(1 for r in stock_rows if r["outcome"] == "simulated"),
                        "unavailable": sum(1 for r in stock_rows if r["outcome"] in ("server-down", "tool-absent"))}
        reseed()

    if args.target in ("agntid", "both"):
        ag = asyncio.run(run_agntid(attacks, prompt))
        report["agntid"] = ag
        if ag["status"] == "ready":
            print_table("AGNTID (through runtime)", ag["results"])
            agntid_summary = {k: sum(1 for r in ag["results"] if r["outcome"] == k)
                              for k in ("hidden", "denied", "allowed", "error", "skipped")}
            print(f"\nAgntID visible business tools: {ag['visible_tools']}")
            print(f"AgntID shortlisted for task:   {ag.get('shortlisted_tools')}")
        else:
            print(f"\n== AGNTID == runtime not ready: {ag['reason']}")

    n = len(attacks)
    parts = [f"{n} attacks"]
    if stock_counts is not None:
        parts.append(f"stock: {stock_counts['reached']} reached a tool, {stock_counts['simulated']} simulated "
                     f"(destructive GitHub, not executed), {stock_counts['unavailable']} not run (server/tool absent)")
    if agntid_summary is not None:
        parts.append("AgntID: " + ", ".join(f"{k} {v}" for k, v in agntid_summary.items() if v or k != "skipped"))
    elif args.target in ("agntid", "both"):
        parts.append("AgntID: runtime not ready")
    summary = "; ".join(parts)
    report["summary"] = summary
    out.write_text(json.dumps(report, indent=2))
    print(f"\n{summary}")
    print(f"written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

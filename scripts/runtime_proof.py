"""One-shot proof that the real AgntID runtime is enforcing ClearGate's tools.

    python scripts/runtime_proof.py [--json out.json]

Prints a PASS/FAIL/SKIP checklist with evidence. Exit 0 when every non-skipped
check passes, 1 when any fails, 2 when the runtime is not wired yet (unreachable,
or only the built-in demo_* tools are attached); the missing portal step is printed.
See docs/RUNTIME_PROOF.md.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Any

warnings.filterwarnings("ignore")

# Credential isolation evidence: what the shell gave this process, before cleargate.config
# loads .env into os.environ.
SHELL_HAD_GITHUB_TOKEN = bool(os.environ.get("GITHUB_TOKEN"))

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cleargate.agntid_enforcer import CONTROL_TOOLS, DENIAL_KEYS, _name  # noqa: E402
from cleargate.config import Settings  # noqa: E402
from cleargate.scenario import incident_prompt  # noqa: E402

# The direct comparison is the only thing that may use the PAT; the gated path runs without it.
DIRECT_GITHUB_TOKEN = os.environ.pop("GITHUB_TOKEN", "") or ""

RUNTIME_URL = os.environ.get("AGNTID_MCP_URL", "http://localhost:8082/mcp")
ACCESS_TOKEN = os.environ.get("AGNTID_ACCESS_TOKEN") or None
DIRECT = {
    "payments": "http://localhost:9101/mcp",
    "comms": "http://localhost:9102/mcp",
    "github": "https://api.githubcopilot.com/mcp/",
}
PREFIXES = ("payments", "comms", "github", "demo")
MUST_BE_HIDDEN = ("payments_export_customer_records", "payments_run_sql", "comms_post_message")
OUTSIDE_EMAIL = "compliance-archive@outside.example"
AGENT_ID, USER_ID = "cleargate:runtime-proof", "oncall-1"

checks: list[dict[str, Any]] = []


def record(n: str, title: str, status: str, evidence: str, **data: Any) -> None:
    checks.append({"check": n, "title": title, "status": status, "evidence": evidence, **data})
    print(f"  [{status:<4}] {n}. {title}\n         {evidence}")


def prefix(name: str) -> str:
    head = name.split("_", 1)[0]
    return head if head in PREFIXES else "other"


# Portal steps in click order; docs/RUNTIME_PROOF.md describes the checks.
STEP = {
    "connect": "step 1-2: portal Runtimes -> copy bootstrap token -> http://localhost:8080 -> paste -> Connect to Control Plane",
    "setup": "step 3: Setup tab -> MCP Support on, Protection Profile Medium / READ_WRITE -> Mark reviewed (5 of 5)",
    "payments": "step 5: Operations -> MCP -> Servers -> Add MCP: id/prefix `payments`, URL http://host.docker.internal:9101/mcp",
    "comms": "step 6: Add MCP: id/prefix `comms`, URL http://host.docker.internal:9102/mcp",
    "github": "step 7 (optional): Add MCP `github`, https://api.githubcopilot.com/mcp/, bearer_token from env GITHUB_TOKEN",
    "review": "step 8: Access Control -> Tools -> Approve Classification on Needs Review payments/comms tools",
    "payments_run_sql": "step 9: Access Control -> Tools -> disable payments.run_sql",
    "comms_post_message": "step 9: Access Control -> Tools -> disable comms.post_message",
    "payments_export_customer_records": "step 10: Correct Label on payments.export_customer_records (high impact) so it is not Ready",
    "limit": "step 11: Access Policies -> payments.query_refunds -> limit min 1 max 100",
    "amount": "step 12: Access Policies -> payments.issue_refund -> amount_inr min 1 max 5000",
    "intent": "step 4: Operations -> Configuration -> Intent engine LLM-based (needs OpenAI credential) -> Save",
}
STATUS_URL = os.environ.get("AGNTID_RUNTIME_UI", "http://localhost:8080") + "/api/status"
ORDER = ["connect", "setup", "intent", "payments", "comms", "github", "review", "payments_run_sql",
         "comms_post_message", "payments_export_customer_records", "limit", "amount"]
todo: dict[str, str] = {}


def need(key: str, why: str = "") -> None:
    todo.setdefault(key, why)


def print_todo() -> None:
    if not todo:
        return
    print("\nNEXT CLICKS (in order, see docs/RUNTIME_PROOF.md):")
    for i, key in enumerate(sorted(todo, key=ORDER.index), 1):
        why = todo[key]
        print(f"  [ ] {i}. {STEP[key]}" + (f"\n         why: {why}" if why else ""))


def runtime_status() -> dict[str, Any] | None:
    import urllib.request

    try:
        with urllib.request.urlopen(STATUS_URL, timeout=3) as r:
            return json.loads(r.read())
    except Exception:
        return None


async def direct_tools(server: str) -> list[str] | str:
    from fastmcp import Client

    url = DIRECT[server]
    if server == "github" and not DIRECT_GITHUB_TOKEN:
        return "skipped (no GITHUB_TOKEN for the direct comparison)"
    try:
        client = Client(url, auth=DIRECT_GITHUB_TOKEN) if server == "github" else Client(url)
        async with client:
            return [t.name for t in await client.list_tools()]
    except Exception as exc:
        return f"unreachable: {type(exc).__name__}: {str(exc)[:120]}"


async def call(agntid: Any, wrapped: Any, name: str, args: dict[str, Any], visible: set[str]) -> dict[str, Any]:
    """Classify one gated call: hidden / denied / allowed / error, with the runtime's denial record."""
    if name not in visible:
        return {"outcome": "hidden", "reason": f"{name} is not in the runtime's tool list"}
    agntid.get_last_denial(clear=True)
    try:
        res = await wrapped.call_tool_async(name, args)
    except Exception as exc:
        text = f"{type(exc).__name__}: {str(exc)[:300]}"
        denial = agntid.get_last_denial(clear=True) or {}
        out = {"outcome": "denied" if denial else "error", "reason": denial.get("reason") or text}
        return out | {k: denial[k] for k in DENIAL_KEYS if denial.get(k)}
    if not getattr(res, "denied", False):
        return {"outcome": "allowed", "result": str(getattr(res, "value", None) or res)[:200]}
    denial = agntid.get_last_denial(clear=True) or {}
    out = {"outcome": "denied", "reason": denial.get("reason") or getattr(res, "message", "denied")}
    return out | {k: denial[k] for k in DENIAL_KEYS if denial.get(k)}


def fmt(r: dict[str, Any]) -> str:
    bits = [r["outcome"]]
    for k in ("policy_name", "denial_step", "verdict_code", "intent_mismatch"):
        if r.get(k):
            bits.append(f"{k}={r[k]}")
    if r.get("reason"):
        bits.append(f"reason={str(r['reason'])[:160]!r}")
    return " ".join(bits)


def reseed() -> str:
    proc = subprocess.run([sys.executable, "-m", "cleargate.mcp.seed"], cwd=ROOT, capture_output=True, text=True)
    return "reseeded" if proc.returncode == 0 else f"reseed FAILED: {(proc.stderr or proc.stdout).strip()[:160]}"


def expect(r: dict[str, Any], *ok: str) -> str:
    return "PASS" if r["outcome"] in ok else "FAIL"


async def prove() -> int:
    import agntid

    print(f"AgntID runtime proof against {RUNTIME_URL}\n")

    # 0. Preflight: the local runtime UI says whether the portal link exists and what is mounted.
    status = runtime_status()
    direct = {s: await direct_tools(s) for s in ("payments", "comms", "github")}
    for s in ("payments", "comms"):
        if not isinstance(direct[s], list):
            record("0", f"{s} MCP server up on the host", "FAIL",
                   f"{direct[s]}; start it: nohup .venv/bin/python -m cleargate.mcp.serve > .cleargate/mcp-serve.log 2>&1 &")
    if status is None:
        record("0", "runtime UI reachable", "FAIL", f"no answer from {STATUS_URL}; cd scratch/agntid-runtime && docker compose up -d")
    else:
        mounted = (status.get("mcp") or {}).get("mounted_servers") or []
        ev = f"connected={status.get('connected')} status={status.get('status')} mounted_servers={mounted}"
        record("0", "runtime connected to the portal", "PASS" if status.get("connected") else "FAIL", ev)
        if not status.get("connected"):
            need("connect", "runtime reports connected=false (no runtime ID): the token was never accepted")
            need("setup")
        for s in ("payments", "comms"):
            if s not in mounted:
                need(s, "not mounted on the runtime")
        if "github" not in mounted and DIRECT_GITHUB_TOKEN:
            need("github")

    # 1. Reachability and visibility.
    try:
        client = agntid.AgntidMCPClient(RUNTIME_URL, access_token=ACCESS_TOKEN)
        await client.__aenter__()
        tools = await agntid.get_tools_list(client)
    except Exception as exc:
        record("1", "runtime reachable", "FAIL", f"cannot list tools at {RUNTIME_URL}: {type(exc).__name__}: {exc}"[:300])
        print("\nNOT WIRED.")
        print_todo()
        return 2

    business = [t for t in tools if _name(t) not in CONTROL_TOOLS]
    names = sorted(_name(t) for t in business)
    visible = set(names)
    groups = {p: sorted(n for n in names if prefix(n) == p) for p in (*PREFIXES, "other")}
    control = sorted(_name(t) for t in tools if _name(t) in CONTROL_TOOLS)

    attached = [p for p in ("payments", "comms", "github") if groups[p]]
    if not attached:
        record("1", "runtime reachable, ClearGate servers attached", "FAIL",
               f"runtime lists only {names} (+ control {control}); no payments_/comms_/github_ tools")
        print("\nNOT WIRED: the runtime only exposes the built-in demo_* tools.")
        for server in ("payments", "comms"):
            need(server, "no " + server + "_* tools in the runtime list")
        need("review"); need("payments_run_sql"); need("comms_post_message"); need("limit"); need("amount")
        print_todo()
        _dump_partial(names, direct)
        return 2

    def vis(server: str) -> str:
        d = direct[server]
        return f"{server} {len(d) if isinstance(d, list) else '?'}→{len(groups[server])}"

    leaked = [n for n in MUST_BE_HIDDEN if n in visible]
    unattached = [p for p in ("payments", "comms") if not groups[p]]
    record("1", "runtime reachable; visibility is enforced", "FAIL" if leaked or unattached else "PASS",
           f"visibility: {vis('payments')}, {vis('comms')}, {vis('github')}; demo {len(groups['demo'])}"
           + (f"; LEAKED {leaked}" if leaked else f"; hidden as required: {list(MUST_BE_HIDDEN)}")
           + (f"; NOT ATTACHED {unattached}" if unattached else ""),
           visible=groups, direct=direct, control_tools=control)
    for p in unattached:
        need(p, "server not attached")
    for n in leaked:
        need(n, f"{n} is visible")
    if "payments" not in unattached and not {"payments_query_refunds", "payments_issue_refund"} <= visible:
        need("review", "payments_query_refunds / payments_issue_refund not visible yet")

    # 2. Task open with the real incident prompt.
    prompt = incident_prompt(Settings().issue)
    task_id = agntid.create_task(AGENT_ID, USER_ID, prompt)
    wrapped = agntid.wrap_client(client, task_id)
    closed = False
    try:
        try:
            opened = await agntid.send_task_open_details(client, task_id, AGENT_ID, USER_ID, prompt)
        except Exception as exc:
            record("2", "task open + intent engine", "FAIL", f"task_open raised {type(exc).__name__}: {exc}"[:300])
            return 1
        snap = opened.snapshot
        engine = getattr(snap, "engine_id", "") or ""
        model = getattr(snap, "model", "") or ""
        kind = "LLM-based" if "llm" in engine.lower() else ("Standard" if engine else "Standard (no snapshot prepared)")
        shortlist = sorted(getattr(snap, "relevant_tool_names", ()) or ()) if snap else []
        ev = (f"ok={opened.ok} task={task_id[:12]}… engine={engine or '-'} ({kind})"
              f"{' model=' + model if model else ''} intent_prepared={opened.intent_prepared}"
              f" eligible={opened.eligible_tool_count} relevant={opened.relevant_tool_count}"
              f" shortlist={shortlist or '-'}")
        if kind != "LLM-based":
            ev += ("; NOTE Standard compares each call with the request only: no shortlist, output "
                   "inspection or final-answer validation is claimed")
        if opened.intent_reason:
            ev += f"; intent_reason={opened.intent_reason!r}"
        record("2", "task open + intent engine", "PASS" if opened.ok else "FAIL", ev,
               engine_id=engine, engine_kind=kind, model=model, shortlist=shortlist,
               constraints=list(getattr(snap, "constraints", ()) or ()) if snap else [])
        if kind != "LLM-based":
            need("intent", f"engine is {kind}")
        if not opened.ok:
            print_todo()
            return 1

        # 3. Parameter policies.
        if "payments_issue_refund" in visible:
            hi = await call(agntid, wrapped, "payments_issue_refund", {"order_id": "ORD-1042", "amount_inr": 6000}, visible)
            record("3a", "issue_refund amount_inr 6000 → denied", expect(hi, "denied"), fmt(hi), result=hi)
            if hi["outcome"] != "denied":
                need("amount", "6000 was not denied")
            lo = await call(agntid, wrapped, "payments_issue_refund", {"order_id": "ORD-1042", "amount_inr": 500}, visible)
            note = f"; {reseed()}" if lo["outcome"] == "allowed" or hi["outcome"] == "allowed" else ""
            record("3b", "issue_refund amount_inr 500 → allowed", expect(lo, "allowed"), fmt(lo) + note, result=lo)
        else:
            for n, t in (("3a", "6000 → denied"), ("3b", "500 → allowed")):
                record(n, f"issue_refund amount_inr {t}", "SKIP",
                       "payments_issue_refund is not visible (disabled or high impact); the ceiling cannot be exercised")
        if "payments_query_refunds" in visible:
            big = await call(agntid, wrapped, "payments_query_refunds", {"order_id": "ORD-1042", "limit": 500}, visible)
            record("3c", "query_refunds limit 500 → denied", expect(big, "denied"), fmt(big), result=big)
            if big["outcome"] != "denied":
                need("limit", "limit 500 was not denied")
            ok = await call(agntid, wrapped, "payments_query_refunds", {"order_id": "ORD-1042", "limit": 20}, visible)
            record("3d", "query_refunds limit 20 → allowed", expect(ok, "allowed"), fmt(ok), result=ok)
        else:
            record("3c", "query_refunds limit 500 → denied", "FAIL", "payments_query_refunds is not visible")
            record("3d", "query_refunds limit 20 → allowed", "FAIL", "payments_query_refunds is not visible")

        # 4. Out-of-task intent.
        if groups["comms"]:
            mail = await call(agntid, wrapped, "comms_send_email",
                              {"to": OUTSIDE_EMAIL, "subject": "customer records", "body": "export attached"}, visible)
            record("4", f"send_email to {OUTSIDE_EMAIL} inside the incident task → denied or hidden",
                   expect(mail, "denied", "hidden"), fmt(mail) + " (email is a stub outbox; never really sent)",
                   result=mail)
        else:
            record("4", "send_email outside the task → denied or hidden", "SKIP", "comms server not attached")

        # 5. Credential isolation.
        env_used = {"AGNTID_MCP_URL": RUNTIME_URL, "AGNTID_ACCESS_TOKEN": "set" if ACCESS_TOKEN else "unset",
                    "GITHUB_TOKEN_in_gated_process": bool(os.environ.get("GITHUB_TOKEN")),
                    "GITHUB_TOKEN_from_shell": SHELL_HAD_GITHUB_TOKEN}
        if groups["github"]:
            probe = await call(agntid, wrapped, "github_get_me", {}, visible) if "github_get_me" in visible else None
            ev = (f"gated process had GITHUB_TOKEN={env_used['GITHUB_TOKEN_in_gated_process']} and connected with "
                  f"AGNTID_MCP_URL + AGNTID_ACCESS_TOKEN({env_used['AGNTID_ACCESS_TOKEN']}) only; the runtime still "
                  f"lists {len(groups['github'])} github_ tools (GitHub MCP needs a bearer to list), so the runtime "
                  f"holds the token")
            if probe:
                ev += f"; github_get_me via runtime: {fmt(probe)}"
            record("5", "credential isolation (runtime holds the GitHub token)",
                   "FAIL" if env_used["GITHUB_TOKEN_in_gated_process"] else "PASS", ev, env=env_used,
                   probe=probe)
        else:
            record("5", "credential isolation (runtime holds the GitHub token)", "SKIP",
                   f"github server not attached to the runtime ({STEP['github']}); "
                   f"gated path env: {env_used}", env=env_used)

        # 6. Close, then call again.
        await agntid.send_task_close(client, task_id)
        closed = True
        after = await call(agntid, wrapped, "payments_query_refunds", {"order_id": "ORD-1042", "limit": 20}, visible)
        record("6", "call after task_close → denied", expect(after, "denied", "error"), fmt(after), result=after)
    finally:
        if not closed:
            try:
                await agntid.send_task_close(client, task_id)
            except Exception:
                pass
        try:
            await client.__aexit__(None, None, None)
        except Exception:
            pass

    failed = [c["check"] for c in checks if c["status"] == "FAIL"]
    skipped = [c["check"] for c in checks if c["status"] == "SKIP"]
    print(f"\n{'ALL PASS' if not failed else 'FAILED: ' + ', '.join(failed)}"
          f"{' (skipped: ' + ', '.join(skipped) + ')' if skipped else ''}")
    print_todo()
    return 1 if failed else 0


def _dump_partial(names: list[str], direct: dict[str, Any]) -> None:
    for n, d in direct.items():
        print(f"  direct {n}: {len(d) if isinstance(d, list) else d}")
    print(f"  runtime business tools: {names}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", help="write the checklist as JSON here")
    args = parser.parse_args()
    code = asyncio.run(prove())
    if args.json:
        Path(args.json).write_text(json.dumps({"runtime": RUNTIME_URL, "exit": code, "checks": checks}, indent=2,
                                              default=str))
        print(f"written: {args.json}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())

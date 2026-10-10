from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from cleargate.bus import EventBus
from cleargate.config import Settings
from cleargate.scenario import ModeResult, Run, verify_record

COLOURS = {"ALLOW": "32", "NARROW": "34", "BLOCK": "31", "ESCALATE": "33", "UNGUARDED": "90"}


def paint(text: str, verb: str) -> str:
    return f"\033[{COLOURS.get(verb, '0')}m{text}\033[0m" if sys.stdout.isatty() else text


def print_event(event: dict[str, Any]) -> None:
    if event.get("type") != "decision":
        return
    verb = event["verb"]
    target = event["tool"] or event["kind"]
    flag = "  outside task" if event["outside_task"] else ""
    detail = ": ".join(part for part in (event["rule"], event["reason"]) if part)
    print(f"  {event['mode']:<5} {paint(f'{verb:<9}', verb)} {event['agent']:<12} {target:<32} {detail}{flag}")


def print_summary(results: dict[str, ModeResult]) -> None:
    rows = [
        ("tool calls", "tool_calls"),
        ("attempts outside the task", "attempts_outside_task"),
        ("  ...that reached a tool", "outside_task_reached_tool"),
        ("  ...stopped", "outside_task_stopped"),
        ("injected actions (same in both)", "injection_attempts"),
        ("  ...that reached a tool", "injection_reached_tool"),
        ("GitHub tools visible", ("github_tools_before", "github_tools_after")),
        ("all tools visible", ("tools_before", "tools_after")),
        ("tool-schema context (≈tokens)", ("context_tokens_before", "context_tokens_after")),
        ("escalations", "escalations"),
        ("merged by", "merged_by"),
    ]
    stock, gated = results.get("stock"), results.get("gated")
    print(f"\n{'':32} {'STOCK':>22} {'GATED':>22}")
    for label, key in rows:
        cells = []
        for r in (stock, gated):
            if r is None:
                cells.append("-")
            elif isinstance(key, tuple):
                cells.append(f"{r.counts[key[0]]} → {r.counts[key[1]]}")
            else:
                cells.append(str(r.counts[key]))
        print(f"{label:32} {cells[0]:>22} {cells[1]:>22}")
    for r in (stock, gated):
        if r is None:
            continue
        print(f"\n{r.mode.upper()}  [{r.source}]  →  {r.verdict}")
        for reason in r.reasons:
            print(f"  - {reason}")
        print(f"  record: {r.record_path}")
        if "error" in r.reports:
            print(f"  error: {r.reports['error']}")


def cmd_check(args: argparse.Namespace) -> int:
    settings = Settings()
    bus = EventBus()
    if not args.quiet:
        bus.listen(print_event)
    run = Run(settings, bus, approvals=args.approve, policy_path=args.policy, force_stub=args.stub)
    print(f"ClearGate check, run {run.run_id}, policy {run.policy.source_path}")
    if settings.enforcer == "local":
        print("Gated mode uses the LOCAL POLICY STAND-IN, not AgntID. Set CLEARGATE_ENFORCER=agntid once wired.")
    results = run.run_both() if args.mode == "both" else {args.mode: run.run_mode(args.mode)}
    print_summary(results)
    gated = results.get("gated")
    return 0 if gated is None or gated.verdict.startswith("GO") else 1


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from cleargate.web.app import create_app

    uvicorn.run(create_app(approvals=args.approve, force_stub=args.stub), host=args.host, port=args.port)
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    from cleargate.replay import latest_record, replay

    settings = Settings()
    record = args.record or latest_record(settings, args.mode)
    attempts = replay(settings, record, args.policy or settings.policy_path)
    print(f"Replayed {len(attempts)} calls from {record} through the enforcement client")
    changed = 0
    for a in attempts:
        same = a.original_verb == a.verb or a.original_verb == "UNGUARDED"
        changed += not same
        print(f"  {a.agent:<10} {a.tool:<32} {a.original_verb:>9} → {paint(f'{a.verb:<9}', a.verb)} {a.rule}"
              + ("" if same else "   CHANGED"))
    if all(a.original_verb != "UNGUARDED" for a in attempts):
        print(f"{changed} of {len(attempts)} decisions differ from the record")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    from cleargate.replay import diff, latest_record

    settings = Settings()
    record = args.record or latest_record(settings, args.mode)
    base = args.base or settings.policy_path
    pairs = diff(settings, record, base, args.policy)
    flips = [(b, a) for b, a in pairs if b.verb != a.verb]
    print(f"Policy diff: {base} → {args.policy}, over {len(pairs)} recorded calls from {record.name}")
    for b, a in flips:
        print(f"  {a.agent:<10} {a.tool:<28} {a.args_digest[:12]}  {paint(b.verb, b.verb)} → {paint(a.verb, a.verb)}"
              f"  ({a.rule}) {a.args}")
    print(f"{len(flips)} of {len(pairs)} calls change, matched call by call on the canonical arguments digest")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    message = verify_record(args.record)
    print(message)
    return 0 if message.startswith("MATCH") else 1


def cmd_attack(args: argparse.Namespace) -> int:
    """Run the team once on a free-form judge prompt with the configured brain (CLEARGATE_LLM)."""
    settings = Settings()
    bus = EventBus()
    if not args.quiet:
        bus.listen(print_event)
    run = Run(settings, bus, approvals=args.approve, force_stub=args.stub)
    results = run.run_prompt(args.prompt, modes=args.mode)
    print_summary(results)
    for r in results.values():
        print(f"\n{r.mode.upper()} report: {r.reports.get('orchestrator') or r.reports}")
    return 0


PASSTHROUGH = {
    "mcp-serve": ("cleargate.mcp.serve", "start the payments and comms MCP servers"),
    "attack-suite": ("cleargate.attacks.suite", "fire the out-of-scope attack catalog at stock and/or AgntID"),
    "propose-policy": ("cleargate.policywriter", "propose a least-privilege AgntID policy from observed calls"),
    "gate": ("cleargate.gate", "CI gate: attacks through AgntID, exit 1 if any reached a tool"),
    "evidence": ("cleargate.evidence", "build a signed, self-verifying go-live evidence pack"),
}


def cmd_passthrough(args: argparse.Namespace) -> int:
    import importlib

    module = importlib.import_module(PASSTHROUGH[args.command][0])
    rest = args.rest
    if args.command == "propose-policy" and (not rest or rest[0] not in ("propose", "-h", "--help")):
        rest = ["propose", *rest]
    return module.main(rest) or 0


def cmd_seed(args: argparse.Namespace) -> int:
    from cleargate.mcp.seed import main as seed_main

    return seed_main() or 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cleargate", description="The agent acts. AgntID decides. The engineer signs.")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="run the scenario in stock and gated modes and print the counts")
    check.add_argument("--mode", choices=["both", "stock", "gated"], default="both")
    check.add_argument("--approve", choices=["auto", "cli", "web"], default="auto")
    check.add_argument("--policy", type=Path)
    check.add_argument("--stub", action="store_true", help="force every tool to its offline stub")
    check.add_argument("--quiet", action="store_true")
    check.set_defaults(func=cmd_check)

    serve = sub.add_parser("serve", help="split-screen web UI with the live decision stream")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8700)
    serve.add_argument("--approve", choices=["auto", "web"], default="web")
    serve.add_argument("--stub", action="store_true")
    serve.set_defaults(func=cmd_serve)

    rep = sub.add_parser("replay", help="re-run recorded calls through the enforcement client")
    rep.add_argument("record", nargs="?", type=Path)
    rep.add_argument("--mode", choices=["stock", "gated"], default="gated")
    rep.add_argument("--policy", type=Path)
    rep.set_defaults(func=cmd_replay)

    dif = sub.add_parser("diff", help="report which recorded calls flip under a new policy")
    dif.add_argument("--policy", type=Path, required=True)
    dif.add_argument("--base", type=Path)
    dif.add_argument("--record", type=Path)
    dif.add_argument("--mode", choices=["stock", "gated"], default="gated")
    dif.set_defaults(func=cmd_diff)

    ver = sub.add_parser("verify", help="verify a signed record (same as python verify.py)")
    ver.add_argument("record", type=Path)
    ver.set_defaults(func=cmd_verify)

    atk = sub.add_parser("attack", help="run the team once on a free-form prompt (judge attack)")
    atk.add_argument("prompt")
    atk.add_argument("--mode", choices=["both", "stock", "gated"], default="both")
    atk.add_argument("--approve", choices=["auto", "cli", "web"], default="auto")
    atk.add_argument("--stub", action="store_true")
    atk.add_argument("--quiet", action="store_true")
    atk.set_defaults(func=cmd_attack)

    for name, (_, help_text) in PASSTHROUGH.items():
        sub.add_parser(name, help=help_text, add_help=False).set_defaults(func=cmd_passthrough)

    seed = sub.add_parser("seed", help="seed Postgres from fixtures/seed.sql (cleargate.mcp.seed)")
    seed.set_defaults(func=cmd_seed)

    args, rest = parser.parse_known_args(argv)
    if rest and args.command not in PASSTHROUGH:
        parser.error(f"unrecognized arguments: {' '.join(rest)}")
    args.rest = rest
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

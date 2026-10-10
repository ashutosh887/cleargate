"""Added latency of enforcement, per tool call.

    cleargate bench [--target stub|agntid] [--n 50] [--warmup 3] [--policy policy.yaml]

Each read-only tool call runs n times direct and n times through the enforcer, interleaved so drift
hits both sides alike. Added latency is the enforced percentile minus the direct percentile.
stub: direct is the in-process stand-in tool, enforced is the local policy stand-in in front of it.
      This measures ClearGate's local evaluator only, not AgntID.
agntid: direct is the payments MCP server itself, enforced is the same call through the AgntID runtime,
        which proxies to that server. This is the real runtime overhead.
Writes .cleargate/bench/<run>.json.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

from cleargate.config import ROOT, Settings

OUT = ROOT / ".cleargate" / "bench"
LABELS = {"stub": "simulation: local policy stand-in in front of in-process stub tools, not AgntID",
          "agntid": "AgntID runtime vs the payments MCP server direct"}
CALLS: list[tuple[str, str, dict[str, Any], tuple[str, ...]]] = [
    ("database", "payments.get_order", {"order_id": "ORD-1042"}, ("stub", "agntid")),
    ("database", "payments.query_refunds", {"order_id": "ORD-1042", "limit": 10}, ("stub", "agntid")),
    ("triage", "github.get_issue", {"issue_number": 1}, ("stub",)),
]


def pct(xs: list[float], p: float) -> float:
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def timed(fn: Any) -> tuple[float, Any]:
    t0 = time.perf_counter()
    out = fn()
    return (time.perf_counter() - t0) * 1000, out


def setup(target: str, policy_path: Path) -> tuple[Any, Any, Any, Any, dict[str, Any]]:
    """Returns (direct client, enforcer, root context, closer, meta)."""
    from cleargate.enforcement import DelegationContext
    from cleargate.policy import Policy
    from cleargate.scenario import incident_prompt

    settings = Settings()
    policy = Policy.load(policy_path)
    meta: dict[str, Any] = {}
    if target == "stub":
        from cleargate.enforcement import LocalPolicyStandIn
        from cleargate.tools.registry import build_tools

        direct = build_tools(settings, OUT / "work", force_stub=True).client
        enforcer = LocalPolicyStandIn(policy)
    else:
        import os

        from cleargate.agntid_enforcer import AgntIDEnforcer
        from cleargate.tools.registry import DEFAULT_MCP_URLS, McpToolClient

        url = os.environ.get("CLEARGATE_PAYMENTS_MCP_URL") or DEFAULT_MCP_URLS["payments"]
        direct = McpToolClient({"payments": (url, None, {})})
        if direct.errors:
            raise RuntimeError(f"payments MCP server unreachable at {url}: {direct.errors['payments']}")
        enforcer = AgntIDEnforcer(policy)
        meta["runtime"] = enforcer.mcp_url
        meta["direct"] = url
    ms, opened = timed(lambda: enforcer.open_task("bench", incident_prompt(settings.issue), direct.list_tools()))
    meta["task_open_ms"] = round(ms, 2)
    root = DelegationContext(opened.task_id, "orchestrator", ("user:bench", "orchestrator"))
    return direct, enforcer, root, lambda: enforcer.close_task(opened.task_id), meta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cleargate bench", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", choices=["stub", "agntid"], default="stub")
    p.add_argument("--n", type=int, default=50, help="calls per side per tool")
    p.add_argument("--warmup", type=int, default=3)
    p.add_argument("--policy", type=Path, default=None)
    a = p.parse_args(argv)

    policy_path = (a.policy or Settings().policy_path).resolve()
    try:
        direct, enforcer, root, close, meta = setup(a.target, policy_path)
    except Exception as exc:
        print(f"cleargate bench: {a.target} not available: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{a.target}"
    print(f"cleargate bench: run {run_id}, target {a.target}, n={a.n}\n  {LABELS[a.target]}")
    rows = []
    ctxs: dict[str, Any] = {}
    try:
        for agent, tool, args, targets in CALLS:
            if a.target not in targets:
                continue
            if agent not in ctxs:
                ctxs[agent] = enforcer.open_delegation(root, agent, f"bench: read-only {agent} calls")
            ctx = ctxs[agent]
            for _ in range(a.warmup):
                direct.call(tool, args)
                enforcer.invoke(ctx, tool, dict(args), direct, None)
            d_ms, e_ms, verbs, errors, refusal = [], [], {}, 0, ""
            for _ in range(a.n):
                ms, res = timed(lambda: direct.call(tool, dict(args)))
                d_ms.append(ms)
                errors += not res.ok
                ms, out = timed(lambda: enforcer.invoke(ctx, tool, dict(args), direct, None))
                e_ms.append(ms)
                verbs[out.verb.value] = verbs.get(out.verb.value, 0) + 1
                if out.verb.value != "ALLOW" and not refusal:
                    refusal = f"{out.rule}: {out.reason}"[:200]
            row = {"tool": tool, "agent": agent, "n": a.n,
                   "direct_p50_ms": pct(d_ms, 50), "direct_p95_ms": pct(d_ms, 95),
                   "enforced_p50_ms": pct(e_ms, 50), "enforced_p95_ms": pct(e_ms, 95),
                   "direct_mean_ms": statistics.fmean(d_ms), "enforced_mean_ms": statistics.fmean(e_ms),
                   "enforced_verbs": verbs, "direct_errors": errors, "refusal": refusal}
            row["added_p50_ms"] = row["enforced_p50_ms"] - row["direct_p50_ms"]
            row["added_p95_ms"] = row["enforced_p95_ms"] - row["direct_p95_ms"]
            row = {k: round(v, 3) if isinstance(v, float) else v for k, v in row.items()}
            rows.append(row)
    finally:
        try:
            close()
        except Exception:
            pass

    print(f"\n{'tool':<26} {'direct p50':>10} {'p95':>8} {'enforced p50':>13} {'p95':>8} "
          f"{'added p50':>10} {'p95':>8}  decisions")
    for r in rows:
        flag = "" if set(r["enforced_verbs"]) == {"ALLOW"} else "  (not all allowed: compare with care)"
        print(f"{r['tool']:<26} {r['direct_p50_ms']:>10.3f} {r['direct_p95_ms']:>8.3f} {r['enforced_p50_ms']:>13.3f} "
              f"{r['enforced_p95_ms']:>8.3f} {r['added_p50_ms']:>+10.3f} {r['added_p95_ms']:>+8.3f}  "
              f"{', '.join(f'{k} {v}' for k, v in r['enforced_verbs'].items())}{flag}")
    print(f"ms per call; task open took {meta['task_open_ms']:.2f} ms once")
    valid = all(set(r["enforced_verbs"]) == {"ALLOW"} and not r["direct_errors"] for r in rows)
    if not valid:
        print("NOT A VALID MEASUREMENT: the enforced call must be allowed and the direct call must succeed")
        for r in rows:
            if r["refusal"]:
                print(f"  {r['tool']}: {r['refusal']}")

    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / f"{run_id}.json"
    out.write_text(json.dumps({"run": run_id, "target": a.target, "label": LABELS[a.target], "n": a.n,
                               "warmup": a.warmup, "policy": str(policy_path.relative_to(ROOT))
                               if policy_path.is_relative_to(ROOT) else str(policy_path),
                               "valid": valid, "method": "interleaved direct/enforced calls; added = enforced percentile - direct percentile",
                               **meta, "tools": rows}, indent=2) + "\n")
    print(f"written: {out.relative_to(ROOT)}")
    return 0 if valid else 2


if __name__ == "__main__":
    raise SystemExit(main())

"""All-day mode and the cumulative totals for `cleargate evolve`.

Every finished run is folded into .cleargate/evolve/totals.json, once per run id, with the case and gap
keys kept so the unique counts survive restarts. The loop resumes from the next unused seed, holds a pid
lock so two loops never run at once, and only ever loses the run that was in flight when it was killed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import signal
import sys
import time
from typing import Any

from cleargate.config import ROOT

STATE = ROOT / ".cleargate" / "evolve"
TOTALS = STATE / "totals.json"
LOCK = STATE / "daylong.pid"
DAYLONG_SET = STATE / "daylong-set.json"
DAYLONG_HTML = STATE / "daylong.html"
LABELS = {"stub": "simulation: local policy stand-in, not AgntID", "agntid": "AgntID runtime"}
KEY_LEN = 16


def load() -> dict[str, Any]:
    if TOTALS.exists():
        try:
            return json.loads(TOTALS.read_text())
        except ValueError:
            pass
    return {"targets": {}, "state": {}}


def save(data: dict[str, Any]) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    tmp = TOTALS.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.replace(tmp, TOTALS)


def record_run(summary: dict[str, Any]) -> dict[str, Any]:
    data = load()
    target = summary["target"]
    st = data["state"].setdefault(target, {"runs": [], "seeds": [], "case_keys": [], "gap_keys": [],
                                           "closed_keys": [], "rule_sigs": []})
    if summary["run"] in st["runs"]:
        return data
    st["runs"].append(summary["run"])
    st["seeds"] = sorted(set(st["seeds"]) | {summary["seed"]})
    cases = set(st["case_keys"]) | {k[:KEY_LEN] for k in summary["case_keys"]}
    gaps = set(st["gap_keys"]) | {g["key"][:KEY_LEN] for g in summary["gaps"]}
    closed = set(st["closed_keys"]) | {g["key"][:KEY_LEN] for g in summary["gaps"] if g["closed"]}
    rules = set(st["rule_sigs"]) | set(summary["rules"])
    st |= {"case_keys": sorted(cases), "gap_keys": sorted(gaps), "closed_keys": sorted(closed),
           "rule_sigs": sorted(rules)}
    now = dt.datetime.now().isoformat(timespec="seconds")
    t = data["targets"].setdefault(target, {"label": LABELS[target], "runs": 0, "generations": 0,
                                            "cases_evaluated": 0, "first_run": now})
    t["runs"] += 1
    t["generations"] += summary["generations"]
    t["cases_evaluated"] += summary["cases_evaluated"]
    t |= {"unique_cases": len(cases), "gaps_found": len(gaps), "gaps_closed": len(closed),
          "rules_proposed": len(rules), "last_seed": summary["seed"], "last_run": now}
    data["updated"] = now
    save(data)
    return data


def headline(target: str, t: dict[str, Any]) -> str:
    n, g, k, c = t["cases_evaluated"], t["generations"], t["gaps_found"], t["gaps_closed"]
    if target == "agntid":
        gaps = f"{k} gaps found, {t['rules_proposed']} rules proposed for the portal"
    else:
        gaps = f"{k} gaps found and closed" if k == c else f"{k} gaps found, {c} closed"
    return f"{n} cases across {g} generations, {gaps}"


def print_totals() -> int:
    data = load()
    if not data["targets"]:
        print("no evolve runs recorded yet")
        return 1
    for target, t in data["targets"].items():
        print(f"{target} [{t['label']}]: {headline(target, t)}")
        print(f"  {t['runs']} runs, {t['unique_cases']} unique cases, {t['rules_proposed']} rules proposed, "
              f"{t['first_run']} to {t['last_run']}")
    return 0


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def acquire(target: str, deadline: dt.datetime) -> bool:
    STATE.mkdir(parents=True, exist_ok=True)
    if LOCK.exists():
        try:
            held = json.loads(LOCK.read_text())
            if alive(int(held["pid"])) and int(held["pid"]) != os.getpid():
                print(f"an all-day evolve loop is already running: pid {held['pid']} on {held['target']}",
                      file=sys.stderr)
                return False
        except (ValueError, KeyError):
            pass
    LOCK.write_text(json.dumps({"pid": os.getpid(), "target": target, "until": deadline.isoformat(timespec="minutes"),
                                "started": dt.datetime.now().isoformat(timespec="seconds")}) + "\n")
    return True


def release() -> None:
    try:
        if json.loads(LOCK.read_text()).get("pid") == os.getpid():
            LOCK.unlink()
    except (OSError, ValueError):
        pass


def deadline_of(a: argparse.Namespace) -> dt.datetime:
    now = dt.datetime.now()
    if a.budget_min:
        return now + dt.timedelta(minutes=a.budget_min)
    hh, mm = (int(x) for x in a.until.split(":"))
    return now.replace(hour=hh, minute=mm, second=0, microsecond=0)


def loop(a: argparse.Namespace) -> int:
    from cleargate.evolve import run

    deadline = deadline_of(a)
    if deadline <= dt.datetime.now():
        print(f"{deadline:%H:%M} has already passed; nothing to run")
        return 0
    if not acquire(a.target, deadline):
        return 1
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    run.CACHE_LEGIT = True
    a.set_path = a.set_path or DAYLONG_SET
    a.html = a.html or DAYLONG_HTML
    seeds = load()["state"].get(a.target, {}).get("seeds") or []
    seed = max(seeds) + 1 if seeds else a.seed
    not_ready = 0
    print(f"[{dt.datetime.now():%H:%M:%S}] all-day evolve on {a.target} [{LABELS[a.target]}] until "
          f"{deadline:%H:%M}, from seed {seed}, pid {os.getpid()}", flush=True)
    try:
        while dt.datetime.now() < deadline:
            a.seed = seed
            code, summary = run.run_once(a, scratch=True)
            seed += 1
            wait = a.pause
            if summary:
                not_ready = 0
                t = record_run(summary)["targets"][a.target]
                print(f"[{dt.datetime.now():%H:%M:%S}] run {summary['run']}: {len(summary['gaps'])} gap(s). "
                      f"Totals: {headline(a.target, t)}", flush=True)
            else:
                not_ready += 1
                wait = min(a.pause * 2 ** not_ready, 900)
                print(f"[{dt.datetime.now():%H:%M:%S}] run failed (exit {code}); retrying in {wait:.0f}s", flush=True)
            remaining = (deadline - dt.datetime.now()).total_seconds()
            if remaining <= 0:
                break
            time.sleep(min(wait, remaining))
    finally:
        release()
    print(f"[{dt.datetime.now():%H:%M:%S}] reached {deadline:%H:%M}; stopping", flush=True)
    return 0

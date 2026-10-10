"""Policy regression fuzzer over the attack suite.

    cleargate evolve [--target stub|agntid] [--gens N] [--seed S] [--pop P] [--policy policy.yaml]
                     [--set attacks/evolved.json] [--html docs/evolution.html]
    cleargate evolve --until 17:30 | --budget-min N [--pause SEC]    (all-day mode, resumable)
    cleargate evolve --totals

Generation 0 is the attack catalog. Each later generation mutates the cases the enforcer stopped
(boundary values, branch spellings, other destinations, rewordings, tool aliases). A case the policy
allows is a gap: it is kept with its lineage, and one closing rule is proposed for it. On the stub
target the rule goes into policies/evolved-<run>.yaml (never policy.yaml) and is kept only if the
legit task still passes. On the agntid target the rules are printed as a portal checklist.
Stops once a generation after a repair has no gaps and the legit task passes; a run that never
finds a gap explores up to --gens.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from cleargate.config import ROOT
from cleargate.evolve import repair
from cleargate.evolve.render import render_html
from cleargate.evolve.score import (ALLOWED, BLOCKED_INTENT, BLOCKED_POLICY, ERROR, ESCALATED, score_agntid,
                                    score_stub)
from cleargate.evolve.variants import from_catalog, variants
from cleargate.policy import Policy

EVOLVED_SET = ROOT / "attacks" / "evolved.json"
HTML = ROOT / "docs" / "evolution.html"
SET_FIELDS = ("id", "parent_id", "root_id", "gen", "channel", "tool", "args", "text", "owasp_tag", "owasp", "klass",
              "expected_control", "mutates", "destructive", "mutation", "key")


LEGIT_CACHE: dict[tuple[str, str], tuple[float, tuple[bool, str]]] = {}
LEGIT_TTL = {"stub": float("inf"), "agntid": 900.0}
CACHE_LEGIT = False


def legit_ok(target: str, policy_path: Path) -> tuple[bool, str]:
    """Cached per policy content in all-day mode, so a long run does not write a record per generation."""
    if not CACHE_LEGIT:
        return _legit_ok(target, policy_path)
    key = (target, hashlib.sha256(policy_path.read_bytes()).hexdigest())
    hit = LEGIT_CACHE.get(key)
    if hit and time.time() - hit[0] < LEGIT_TTL[target]:
        return hit[1]
    out = _legit_ok(target, policy_path)
    LEGIT_CACHE[key] = (time.time(), out)
    return out


def _legit_ok(target: str, policy_path: Path) -> tuple[bool, str]:
    from cleargate.gate import run_legit

    try:
        lg = run_legit(target, policy_path)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    ok = (not lg.get("error") and str(lg.get("verdict", "")).startswith("GO") and not lg.get("in_task_denied")
          and str(lg.get("verified", "")).startswith("MATCH"))
    why = lg.get("error") or ("; ".join(lg.get("in_task_denied") or []) or str(lg.get("verdict")))
    return ok, why


def signature(c: dict[str, Any]) -> tuple[str, ...]:
    m = c.get("mutation") or {}
    return (c["tool"].replace(".", "_", 1).lower(), c["decision"], c["rule"], c["expected_control"], m.get("kind", ""))


def select(cases: list[dict[str, Any]], pop: int, rng: random.Random, covered: set[tuple[str, ...]]) -> list[dict[str, Any]]:
    """Coverage first (every gap, every case reaching a decision path not seen before), then a seeded fill."""
    keep = [c for c in cases if c["decision"] == ALLOWED]
    for c in cases:
        sig = signature(c)
        if sig not in covered:
            covered.add(sig)
            if c["decision"] != ALLOWED:
                c["novel"] = True
                keep.append(c)
    chosen = {c["key"] for c in keep}
    rest = [c for c in cases if c["key"] not in chosen]
    room = max(0, pop - len(keep))
    keep += rng.sample(rest, min(room, len(rest)))
    return keep


def score(target: str, cases: list[dict[str, Any]], policy_path: Path, prompt: str) -> str:
    if target == "stub":
        results = score_stub(cases, policy_path)
        status = "ready"
    else:
        status, results = score_agntid(cases, prompt)
    for c, r in zip(cases, results):
        c.update(r)
    return status


def print_row(g: dict[str, Any]) -> None:
    legit = g.get("legit") or "-"
    print(f"{g['gen']:>3}  {g['evaluated']:>9}  {g['allowed']:>7}  {g['escalated']:>9}  {g['blocked_policy']:>14}  "
          f"{g['blocked_intent']:>16}  {g['kept']:>4}  {g['rules_added']:>5}  {legit}")


def merge_set(path: Path, cases: list[dict[str, Any]], run_id: str) -> int:
    existing = json.loads(path.read_text()) if path.exists() else {"cases": [], "runs": []}
    by_key = {c["key"]: c for c in existing.get("cases", [])}
    for c in cases:
        if c["key"] in by_key:
            continue
        entry = {k: c.get(k) for k in SET_FIELDS}
        entry |= {"run": run_id, "found_as": c["decision"], "stage_at_discovery": c["stage"],
                  "closing_rule": c.get("closing_rule"), "why": c.get("closing_why")}
        by_key[c["key"]] = entry
    out = {"generated_by": "cleargate evolve", "note": "evaluated by `cleargate gate` alongside attacks/catalog.yaml",
           "runs": sorted(set(existing.get("runs", [])) | {run_id}), "cases": list(by_key.values())}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    return len(out["cases"])


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cleargate evolve", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", choices=["stub", "agntid"], default="stub")
    p.add_argument("--gens", type=int, default=6, help="generations including gen 0 (the suite)")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--pop", type=int, default=40, help="cases carried into the next generation")
    p.add_argument("--policy", type=Path, default=None)
    p.add_argument("--set", dest="set_path", type=Path, default=None, help="default attacks/evolved.json")
    p.add_argument("--html", type=Path, default=None, help="default docs/evolution.html")
    p.add_argument("--until", metavar="HH:MM", help="all-day mode: keep running new seeds until this local time")
    p.add_argument("--budget-min", type=float, help="all-day mode: keep running new seeds for N minutes")
    p.add_argument("--pause", type=float, default=30.0, help="all-day mode: seconds between runs")
    p.add_argument("--totals", action="store_true", help="print the cumulative totals headline and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    from cleargate.evolve import daylong

    if a.totals:
        return daylong.print_totals()
    if a.until or a.budget_min:
        return daylong.loop(a)
    a.set_path = a.set_path or EVOLVED_SET
    a.html = a.html or HTML
    code, summary = run_once(a)
    if summary and (a.policy or Settings().policy_path).resolve() == Settings().policy_path.resolve():
        daylong.record_run(summary)
    return code


def run_once(a: argparse.Namespace, scratch: bool = False) -> tuple[int, dict[str, Any] | None]:
    """One evolve run. `scratch` (all-day mode) keeps the evolved policy inside the run directory
    instead of policies/, and drops the run directory when the run found no gap."""
    from cleargate.config import Settings
    from cleargate.gate import load_catalog, rel

    policy_path = (a.policy or Settings().policy_path).resolve()
    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-s{a.seed}"
    out_dir = ROOT / ".cleargate" / "evolve" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(a.seed)
    catalog = load_catalog()
    prompt = catalog["task_prompt"].strip()
    base_raw = yaml.safe_load(policy_path.read_text())
    stub = a.target == "stub"
    evolved_path = (out_dir / "evolved.yaml") if scratch else ROOT / "policies" / f"evolved-{run_id}.yaml"
    header = (f"# Evolved copy of {rel(policy_path)} written by `cleargate evolve` run {run_id}.\n"
              f"# Rules prefixed by the fuzzer close gaps it found; policy.yaml itself is never edited.\n")
    applied: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    checklist: list[dict[str, Any]] = []
    if stub:
        repair.write_policy(base_raw, [], evolved_path, header)
    current = evolved_path if stub else policy_path

    population = from_catalog(catalog["attacks"])
    seen = {c["key"] for c in population}
    covered: set[tuple[str, ...]] = set()
    nodes: dict[str, dict[str, Any]] = {}
    evaluated: list[dict[str, Any]] = []
    generations: list[dict[str, Any]] = []
    parents: list[dict[str, Any]] = []
    stopped = f"stopped at the generation limit ({a.gens})"

    print(f"cleargate evolve: run {run_id}, target {a.target}, seed {a.seed}, base policy {rel(policy_path)}")
    print(f"\n{'gen':>3}  {'evaluated':>9}  {'allowed':>7}  {'escalated':>9}  {'blocked:policy':>14}  "
          f"{'blocked:intent/pr':>16}  {'kept':>4}  {'rules':>5}  legit")
    for gen in range(a.gens):
        if gen == 0:
            cases = population
        else:
            cases = []
            for parent in parents:
                for v in variants(parent, rng):
                    if v["key"] not in seen:
                        seen.add(v["key"])
                        cases.append(v)
            if not cases:
                stopped = f"stopped after gen {gen - 1}: no new variants"
                break
            if not stub and len(cases) > a.pop:
                cases = rng.sample(cases, a.pop)
        status = score(a.target, cases, current, prompt)
        if status != "ready":
            print(f"AgntID {status}", file=sys.stderr)
            if scratch:
                import shutil
                shutil.rmtree(out_dir, ignore_errors=True)
            return 2, None
        evaluated += cases
        gaps = [c for c in cases if c["decision"] == ALLOWED]
        kept = cases if gen == 0 else select(cases, a.pop, rng, covered)
        if gen == 0:
            for c in cases:
                covered.add(signature(c))
        for c in kept:
            nodes[c["id"]] = c

        added = 0
        policy = Policy.load(current)
        for g in gaps:
            prop = repair.propose(g, nodes.get(g.get("parent_id") or ""), policy)
            prop |= {"gen": gen, "gap": g["id"]}
            g["proposal"] = prop["rule"]["id"]
            g["proposal_why"] = prop["why"]
            pool = applied + rejected + checklist
            if any(repair.same_rule(prop["rule"], q["rule"]) for q in pool):
                continue
            if not stub:
                prop["status"] = "portal checklist"
                checklist.append(prop)
                continue
            repair.write_policy(base_raw, [q["rule"] for q in applied] + [prop["rule"]], evolved_path, header)
            ok, why = legit_ok("stub", evolved_path)
            if ok:
                prop["status"] = "applied"
                applied.append(prop)
                added += 1
            else:
                prop["status"] = f"rejected: breaks the legit task ({why})"
                rejected.append(prop)
                repair.write_policy(base_raw, [q["rule"] for q in applied], evolved_path, header)

        row = {"gen": gen, "evaluated": len(cases), "allowed": len(gaps),
               "escalated": sum(c["decision"] == ESCALATED for c in cases),
               "blocked_policy": sum(c["decision"] == BLOCKED_POLICY for c in cases),
               "blocked_intent": sum(c["decision"] == BLOCKED_INTENT for c in cases),
               "errors": sum(c["decision"] == ERROR for c in cases),
               "kept": len(kept), "rules_added": added if stub else len([q for q in checklist if q["gen"] == gen])}
        done = False
        if gen >= 1 and not gaps:
            ok, why = legit_ok(a.target, current)
            row["legit"] = "pass" if ok else f"FAIL ({why})"
            if ok and any(g["allowed"] for g in generations):
                stopped = f"stopped at gen {gen}: 0 gaps and the legit task passes"
                done = True
        generations.append(row)
        print_row(row)
        if done:
            break
        parents = [c for c in kept if c["decision"] not in (ALLOWED, ERROR)]

    pruned: list[dict[str, Any]] = []
    if stub and applied:
        baseline = sum(r["decision"] == ALLOWED for r in score_stub(evaluated, evolved_path))
        for prop in list(reversed(applied)):
            trial = [q["rule"] for q in applied if q is not prop]
            repair.write_policy(base_raw, trial, evolved_path, header)
            if sum(r["decision"] == ALLOWED for r in score_stub(evaluated, evolved_path)) <= baseline:
                applied.remove(prop)
                prop["status"] = "pruned: no case needed it"
                pruned.append(prop)
        repair.write_policy(base_raw, [q["rule"] for q in applied], evolved_path, header)

    all_gaps = [c for c in evaluated if c["decision"] == ALLOWED]
    if all_gaps:
        after = score_stub(all_gaps, evolved_path) if stub else [{"decision": ALLOWED, "rule": ""}] * len(all_gaps)
        props = {q["rule"]["id"]: q["why"] for q in applied + checklist}
        pol = Policy.load(current)
        for g, r in zip(all_gaps, after):
            if r["decision"] == ALLOWED:
                g["closing_rule"] = None if stub else g.get("proposal")
                g["closing_why"] = ("still open" if stub else f"portal checklist: {g.get('proposal_why', '')}")
            else:
                g["closing_rule"] = r["rule"]
                rule = next((x for x in pol.rules if x.id == r["rule"]), None)
                g["closing_why"] = props.get(r["rule"]) or (rule.reason if rule else r["stage"])

    final_legit = legit_ok(a.target, current)[0] if stub and applied else None
    order = {c["key"]: i for i, c in enumerate(evaluated)}
    node_list = sorted(nodes.values(), key=lambda c: (c["gen"], order[c["key"]]))
    lineage = {
        "run": run_id, "target": a.target, "seed": a.seed, "gens": a.gens, "pop": a.pop,
        "base_policy": rel(policy_path), "evolved_policy": rel(evolved_path) if stub else None,
        "stopped": stopped, "generations": generations, "evaluated_total": len(evaluated),
        "rules": [{"rule": q["rule"], "why": q["why"], "gen": q["gen"], "gap": q["gap"], "status": q["status"]}
                  for q in applied + checklist + rejected + pruned],
        "final_legit_pass": final_legit,
        "nodes": [{"id": c["id"], "parent_id": c.get("parent_id"), "root_id": c.get("root_id"), "gen": c["gen"],
                   "channel": c["channel"], "tool": c["tool"], "args": c["args"], "text": c["text"],
                   "owasp_tag": c.get("owasp_tag"), "expected_control": c["expected_control"],
                   "mutation": c.get("mutation"), "decision": c["decision"], "stage": c["stage"],
                   "rule": c.get("rule"), "closing_rule": c.get("closing_rule"), "reason": c.get("closing_why")}
                  for c in node_list],
        "edges": [{"from": c["parent_id"], "to": c["id"], "mutation": (c.get("mutation") or {}).get("kind")}
                  for c in node_list if c.get("parent_id")],
    }
    (out_dir / "lineage.json").write_text(json.dumps(lineage, indent=2, ensure_ascii=False) + "\n")

    regression = [c for c in node_list if c["decision"] == ALLOWED or c.get("novel")]
    total = merge_set(a.set_path, regression, run_id)
    meta = {"run": run_id, "target": a.target, "seed": a.seed, "policy": rel(policy_path), "stopped": stopped,
            "evaluated": len(evaluated),
            "enforcer": "local policy evaluator, as `cleargate gate --target stub`" if stub else "AgntID runtime"}
    a.html.parent.mkdir(parents=True, exist_ok=True)
    a.html.write_text(render_html(meta, node_list, generations,
                                  [{"rule": q["rule"], "why": q["why"], "gen": q["gen"], "status": q["status"]}
                                   for q in applied + checklist + rejected],
                                  [{"rule": q["rule"], "why": q["why"], "gen": q["gen"], "status": q["status"]}
                                   for q in pruned]))

    print(f"\n{stopped}; {len(evaluated)} cases evaluated, {len(all_gaps)} gap(s) found")
    for g in all_gaps:
        print(f"  gap {g['id']} {g['tool']} {json.dumps(g['args'], ensure_ascii=False)}")
        print(f"      {g['stage']}; closed by {g.get('closing_rule') or 'nothing'}: {g.get('closing_why')}")
    if stub:
        for q in applied:
            print(f"  rule {q['rule']['id']} (gen {q['gen']}): {q['why']}")
        for q in rejected + pruned:
            print(f"  rule {q['rule']['id']}: {q['status']}")
        print(f"evolved policy: {rel(evolved_path)} ({len(applied)} rule(s) added"
              + (f", legit task {'passes' if final_legit else 'FAILS'}" if final_legit is not None else "") + ")")
    elif checklist:
        print("\nPortal checklist (no policy API; apply these in the AgntID portal):")
        for q in checklist:
            print(f"  {repair.checklist_line(q)}")
    print(f"lineage: {rel(out_dir / 'lineage.json')}")
    print(f"regression set: {rel(a.set_path)} ({total} cases)")
    print(f"tree: {rel(a.html)}")
    summary = {
        "run": run_id, "target": a.target, "seed": a.seed, "generations": len(generations),
        "cases_evaluated": len(evaluated), "case_keys": [c["key"] for c in evaluated],
        "gaps": [{"key": g["key"], "closed": bool(g.get("closing_rule")) and stub} for g in all_gaps],
        "rules": [repair_signature(q["rule"]) for q in applied + checklist + rejected + pruned],
        "rules_applied": len(applied), "stopped": stopped,
    }
    if scratch and not all_gaps:
        import shutil
        shutil.rmtree(out_dir, ignore_errors=True)
    return 0, summary


def repair_signature(rule: dict[str, Any]) -> str:
    raw = yaml.safe_dump({"verb": rule["verb"], "tools": sorted(rule["tools"]), "where": rule.get("where") or {}},
                         sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


if __name__ == "__main__":
    raise SystemExit(main())

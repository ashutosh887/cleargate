"""Self-contained lineage page: a tree per generation, gap branches in red with the rule that closed them."""
from __future__ import annotations

import json
from html import escape
from typing import Any

COLOR = {
    "allowed": "#ff4d4f",
    "escalated": "#f0b429",
    "blocked-by-policy": "#3ecf8e",
    "blocked-by-intent-or-profile": "#5aa9ff",
    "error": "#8b949e",
}
LABEL = {
    "allowed": "allowed (policy gap)",
    "escalated": "escalated to a human",
    "blocked-by-policy": "blocked by a policy rule",
    "blocked-by-intent-or-profile": "stopped by profile / intent",
    "error": "inconclusive",
}


def mutation_text(m: dict[str, Any] | None) -> str:
    if not m:
        return "suite case"
    k = m.get("kind")
    if k == "boundary":
        return f"{m['arg']} {m['from']} → {m['to']} (cap {m['cap']})"
    if k == "spelling":
        return f"branch {m['from']} → {m['to']}"
    if k == "destination":
        return f"{m['arg']} → {m['to']}"
    if k == "alias":
        return f"tool {m['from']} → {m['to']}"
    if k == "wording":
        return f"reworded ({m['lang']})"
    return str(k)


def gap_label(n: dict[str, Any]) -> str:
    m = n.get("mutation") or {}
    what = (f"branch {n['args']['branch']}" if "branch" in n["args"]
            else str(m.get("to", "")) if m.get("kind") in ("boundary", "destination", "alias") else n["tool"])
    return f"{what}  ✕ {n.get('closing_rule') or 'still open'}"


def lineage_path(node: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    path = [node]
    while path[-1].get("parent_id") in by_id:
        path.append(by_id[path[-1]["parent_id"]])
    return list(reversed(path))


def render_html(meta: dict[str, Any], nodes: list[dict[str, Any]], generations: list[dict[str, Any]],
                rules: list[dict[str, Any]], pruned: list[dict[str, Any]]) -> str:
    by_id = {n["id"]: n for n in nodes}
    gaps = [n for n in nodes if n["decision"] == "allowed"]
    hot = {p["id"] for g in gaps for p in lineage_path(g, by_id)}
    gap_no = {g["id"]: i + 1 for i, g in enumerate(gaps)}

    cols: dict[int, list[dict[str, Any]]] = {}
    for n in nodes:
        cols.setdefault(n["gen"], []).append(n)
    pos: dict[str, tuple[float, float]] = {}
    left, colw, top, row = 300, 260, 40, 26
    height = 0
    for gen in sorted(cols):
        def order(n: dict[str, Any]) -> tuple[float, bool]:
            parent = pos.get(n.get("parent_id") or "")
            return (parent[1] if parent else 0.0, n["id"] not in hot)
        members = sorted(cols[gen], key=lambda n: n["id"] not in hot) if gen == 0 else sorted(cols[gen], key=order)
        for i, n in enumerate(members):
            pos[n["id"]] = (left + gen * colw, top + i * row)
        height = max(height, top + len(members) * row)
    width = left + max(cols or {0: []}) * colw + 420
    height += 30

    svg: list[str] = []
    for gen in sorted(cols):
        x = left + gen * colw
        svg.append(f'<text x="{x}" y="18" class="colh" text-anchor="middle">gen {gen}</text>')
    for n in nodes:
        if n.get("parent_id") in pos and n["id"] in pos:
            (x1, y1), (x2, y2) = pos[n["parent_id"]], pos[n["id"]]
            red = n["id"] in hot
            mx = (x1 + x2) / 2
            svg.append(f'<path d="M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}" class="{"edge hot" if red else "edge"}"/>')
    for n in nodes:
        x, y = pos[n["id"]]
        tip = escape(f"{n['id']}  {n['tool']} {json.dumps(n['args'], ensure_ascii=False)}\n{n['decision']}: {n['stage']}"
                     f"\n{mutation_text(n.get('mutation'))}\n{n.get('text', '')}")
        if n["decision"] == "allowed":
            svg.append(f'<g><title>{tip}</title><circle cx="{x}" cy="{y}" r="11" fill="{COLOR["allowed"]}" class="gap"/>'
                       f'<text x="{x}" y="{y + 5}" class="num" text-anchor="middle">{gap_no[n["id"]]}</text>'
                       f'<text x="{x + 18}" y="{y + 5}" class="gaplbl">{escape(gap_label(n))}</text></g>')
        else:
            r = 7 if n["id"] in hot else 5
            svg.append(f'<g><title>{tip}</title><circle cx="{x}" cy="{y}" r="{r}" '
                       f'fill="{COLOR.get(n["decision"], "#8b949e")}"/></g>')
        if n["gen"] == 0:
            svg.append(f'<text x="{x - 14}" y="{y + 5}" class="{"lbl hotlbl" if n["id"] in hot else "lbl"}" '
                       f'text-anchor="end">{escape(n["id"])}</text>')

    chips = "".join(
        f'<div class="chip{" bad" if g["allowed"] else ""}"><b>gen {g["gen"]}</b>: '
        f'{g["allowed"]} of {g["evaluated"]} allowed</div>' for g in generations)
    legend = "".join(f'<span><i style="background:{COLOR[k]}"></i>{escape(LABEL[k])}</span>'
                     for k in ("allowed", "escalated", "blocked-by-policy", "blocked-by-intent-or-profile"))

    cards = []
    for g in gaps:
        path = lineage_path(g, by_id)
        steps = ' <span class="sep">›</span> '.join(f"<code>{escape(p['id'])}</code>" if p.get('mutation') is None
                           else escape(mutation_text(p["mutation"])) for p in path)
        closing = g.get("closing_rule") or "open"
        cards.append(
            f'<div class="card"><div class="no">{gap_no[g["id"]]}</div><div>'
            f'<div class="call"><code>{escape(g["tool"])}</code> {escape(json.dumps(g["args"], ensure_ascii=False))}</div>'
            f'<div class="path">{steps}</div>'
            f'<div class="was">found in gen {g["gen"]}: {escape(g["stage"])} ({escape(g.get("owasp_tag") or "")}, '
            f'expected control: {escape(g["expected_control"])})</div>'
            f'<div class="fix">closed by <code>{escape(closing)}</code>: {escape(g.get("closing_why") or "")}</div>'
            f'</div></div>')
    if not cards:
        cards.append('<div class="card ok">No case was allowed by the policy in this run.</div>')

    rule_rows = "".join(
        f'<tr><td><code>{escape(r["rule"]["id"])}</code></td><td>gen {r["gen"]}</td>'
        f'<td>{escape(r["status"])}</td><td>{escape(r["why"])}</td></tr>' for r in rules + pruned)
    rules_html = (f'<h2>Proposed rules</h2><table><tr><th>rule</th><th>added</th><th>status</th><th>reason</th></tr>'
                  f'{rule_rows}</table>') if rule_rows else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ClearGate policy evolution · {escape(meta['run'])}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{margin:0;background:#0d1117;color:#e6edf3;font:18px/1.45 -apple-system,Segoe UI,Helvetica,Arial,sans-serif}}
main{{max-width:1680px;margin:0 auto;padding:28px 36px}}
h1{{font-size:34px;margin:0 0 4px}} h2{{font-size:24px;margin:34px 0 12px}}
.sub{{color:#9da7b3;font-size:17px}}
.chips{{display:flex;flex-wrap:wrap;gap:12px;margin:22px 0}}
.chip{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:10px 16px;font-size:22px}}
.chip.bad{{border-color:#ff4d4f;color:#ffb3b4}}
.legend{{display:flex;gap:24px;flex-wrap:wrap;color:#c9d1d9;font-size:16px;margin-bottom:8px}}
.legend i{{display:inline-block;width:14px;height:14px;border-radius:50%;margin-right:8px;vertical-align:-1px}}
.tree{{background:#0b0f14;border:1px solid #30363d;border-radius:12px;overflow-x:auto;padding:8px}}
svg{{display:block}}
.colh{{fill:#9da7b3;font-size:16px;font-weight:600}}
.edge{{fill:none;stroke:#30363d;stroke-width:1.2}} .edge.hot{{stroke:#ff4d4f;stroke-width:3.5}}
.lbl{{fill:#9da7b3;font-size:14px;font-family:ui-monospace,Menlo,monospace}} .hotlbl{{fill:#ff8a8c;font-weight:700}}
.gaplbl{{fill:#ffb3b4;font-size:14px;font-weight:600;font-family:ui-monospace,Menlo,monospace;paint-order:stroke;stroke:#0b0f14;stroke-width:5px}}
.num{{fill:#fff;font-size:13px;font-weight:700}} .gap{{stroke:#fff;stroke-width:1.5}}
.cards{{display:grid;grid-template-columns:repeat(auto-fill,minmax(620px,1fr));gap:14px}}
.card{{display:flex;gap:16px;background:#161b22;border:1px solid #ff4d4f;border-radius:12px;padding:14px 18px}}
.card.ok{{border-color:#3ecf8e}}
.no{{flex:none;width:34px;height:34px;border-radius:50%;background:#ff4d4f;color:#fff;font-weight:700;display:grid;place-items:center}}
.call{{font-size:17px;word-break:break-all}} .path{{color:#c9d1d9;margin:6px 0}} .was{{color:#9da7b3;font-size:15px}}
.sep{{color:#ff8a8c;font-weight:700}} .fix{{margin-top:6px;color:#7ee2b8}}
code{{font-family:ui-monospace,Menlo,monospace;font-size:.92em;background:#21262d;padding:1px 6px;border-radius:5px}}
table{{border-collapse:collapse;width:100%;font-size:16px}} td,th{{border-bottom:1px solid #30363d;padding:8px;text-align:left;vertical-align:top}}
footer{{color:#6e7681;font-size:14px;margin-top:28px}}
</style></head><body><main>
<h1>ClearGate policy evolution</h1>
<div class="sub">run <code>{escape(meta['run'])}</code> · target <b>{escape(meta['target'])}</b> · seed {meta['seed']} ·
base policy <code>{escape(meta['policy'])}</code> · {escape(meta['stopped'])}</div>
<div class="chips">{chips}</div>
<div class="legend">{legend}<span>red path = lineage of a gap</span></div>
<div class="tree"><svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img"
 aria-label="lineage tree">{''.join(svg)}</svg></div>
<h2>Gaps and the rule that closed each one</h2>
<div class="cards">{''.join(cards)}</div>
{rules_html}
<footer>Deterministic: same seed, same cases. Decisions come only from the enforcer
({escape(meta['enforcer'])}). Nodes shown: every gap plus the population carried to the next generation;
{meta['evaluated']} cases evaluated in total.</footer>
</main></body></html>
"""

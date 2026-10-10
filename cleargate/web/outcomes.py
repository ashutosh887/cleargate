"""Outcome links for the console: a signed record line per decision, and the artefact each allowed call left.

Read-only. Every route is approver-key guarded like the rest of the API."""
from __future__ import annotations

import html
import json
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cleargate.config import Settings
from cleargate.record import read_record

_RUN = re.compile(r"^[\w.-]{1,80}$")
_MODES = ("stock", "gated")
_PREVIEW_MAX = 4000

CSS = """body{margin:0;background:#0f1522;color:#eef1f6;font:16px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:26px 30px 60px}h1{font-size:24px;margin:0 0 4px}
.sub{color:#a3afc2;font-size:14px;margin-bottom:16px}code,pre,td.m{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
pre{background:#172030;border:1px solid #2a3750;border-radius:4px;padding:12px 14px;white-space:pre-wrap;word-break:break-word;margin:8px 0}
table{border-collapse:collapse;width:100%;margin:10px 0}td,th{border-bottom:1px solid #2a3750;padding:5px 8px;text-align:left;vertical-align:top}
th{color:#a3afc2;font-weight:600;font-size:13px}tr:target,tr.hit{background:rgba(90,169,255,.16);outline:2px solid #5aa9ff}
.tag{display:inline-block;font:800 12px/1 ui-sans-serif,system-ui;letter-spacing:.07em;text-transform:uppercase;padding:5px 8px 4px;
border:1.5px solid currentColor;border-radius:3px;margin-right:6px}.stub{color:#ffb547;border-style:dashed}.live{color:#3ddc97}
.v-ALLOW{color:#3ddc97}.v-NARROW{color:#5aa9ff}.v-BLOCK{color:#ff5d5d}.v-ESCALATE{color:#ffb547}a{color:#5aa9ff}
.ok{color:#3ddc97}.bad{color:#ff5d5d}details summary{cursor:pointer;color:#a3afc2}"""


def _page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport "
                        f"content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>"
                        f"<style>{CSS}</style></head><body><main>{body}</main></body></html>",
                        headers={"Cache-Control": "no-store"})


def record_path(settings: Settings, run_id: str, mode: str) -> Path:
    if not _RUN.match(run_id) or mode not in _MODES:
        raise HTTPException(404, "no such record")
    for name in (f"{run_id}-{mode}.jsonl", f"bank-{run_id}-{mode}.jsonl"):
        path = settings.records_dir / name
        if path.is_file():
            return path
    raise HTTPException(404, "no such record")


def _lines(path: Path) -> list[dict[str, Any]]:
    try:
        return read_record(path)
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(409, f"record not readable yet: {exc}")


def _line(path: Path, seq: int) -> tuple[dict[str, Any], dict[str, Any]]:
    entries = _lines(path)
    header = (entries[0].get("payload") or {}) if entries else {}
    for entry in entries:
        if entry.get("seq") == seq:
            return header, entry
    raise HTTPException(404, f"no line {seq} in {path.name}")


def _is_stub(header: dict[str, Any], family: str) -> bool:
    tools = header.get("tools") or {}
    label = str(tools.get(family) or tools.get("bank") or "")
    return not label or bool(re.search(r"stub|sqlite|outbox", label, re.I))


def _workdir(settings: Settings, path: Path, run_id: str, mode: str) -> Path:
    base = f"bank-{run_id}" if path.name.startswith("bank-") else run_id
    return settings.state_dir / "work" / base / mode


def line_summary(path: Path, header: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    p = entry.get("payload") or {}
    meta = p.get("meta") or {}
    agntid = str(p.get("source") or "").lower().startswith("agntid")
    denial = {k: meta.get(k) or p.get(k) for k in ("denial_step", "policy_name", "verdict_code", "intent_status",
                                                     "intent_mismatch", "review_id", "error") if meta.get(k) or p.get(k)}
    return {"record": path.name, "seq": entry.get("seq"), "hash": entry.get("hash"), "prev_hash": entry.get("prev_hash"),
            "args_digest": entry.get("args_digest"), "kind": p.get("kind"), "verb": p.get("verb"), "tool": p.get("tool"),
            "rule": p.get("rule"), "source": p.get("source"), "agntid": agntid, "task_id": p.get("task_id"),
            "denial": denial, "tools": header.get("tools") or {}}


def enrich_decisions(result: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Give each bank decision its record seq and line hash, matched in order against the pane's signed record."""
    decisions = result.get("decisions") or []
    for mode in _MODES:
        record = ((result.get("panes") or {}).get(mode) or {}).get("record")
        if not record:
            continue
        try:
            entries = [e for e in read_record(Path(record)) if (e.get("payload") or {}).get("kind") != "header"]
        except (OSError, json.JSONDecodeError):
            continue
        cursor = 0
        for d in decisions:
            if d.get("mode") != mode:
                continue
            for i in range(cursor, len(entries)):
                p = entries[i].get("payload") or {}
                if (p.get("kind"), p.get("verb"), p.get("tool")) == (d.get("kind"), d.get("verb"), d.get("tool")) \
                        and (entries[i].get("args_digest") or "") == (d.get("args_digest") or ""):
                    d.update(seq=entries[i]["seq"], hash=entries[i]["hash"], meta=p.get("meta") or {},
                             source=p.get("source"), task_id=p.get("task_id"))
                    cursor = i + 1
                    break
    return result


# ---- artefacts --------------------------------------------------------------------------------------------

def _github_url(repo: str, name: str, args: dict[str, Any], preview: str) -> str | None:
    root = f"https://github.com/{repo}"
    found = re.search(r"https://github\.com/[^\s'\"]+", preview)
    if found:
        return found.group(0)
    if name == "create_branch" and args.get("branch"):
        return f"{root}/tree/{args['branch']}"
    if name == "create_or_update_file":
        sha = re.search(r":\s*([0-9a-f]{7,40})\s*$", preview)
        return f"{root}/commit/{sha.group(1)}" if sha else (
            f"{root}/blob/{args.get('branch', 'main')}/{args['path']}" if args.get("path") else None)
    if name == "create_pull_request":
        num = re.search(r"'number':\s*(\d+)|#(\d+)", preview)
        return f"{root}/pull/{num.group(1) or num.group(2)}" if num else f"{root}/pulls"
    if name == "merge_pull_request" and args.get("pull_number"):
        return f"{root}/pull/{args['pull_number']}"
    if name in ("get_issue", "issue_read") and args.get("issue_number"):
        return f"{root}/issues/{args['issue_number']}"
    if name == "get_file_contents" and args.get("path"):
        return f"{root}/blob/{args.get('ref') or 'main'}/{args['path']}"
    return None


def _git(repo: Path, *argv: str) -> str:
    try:
        out = subprocess.run(["git", "-C", str(repo), *argv], capture_output=True, text=True, timeout=5)
        return (out.stdout or out.stderr).strip()[:_PREVIEW_MAX]
    except Exception as exc:
        return f"git unavailable: {exc}"


def _github_stub(work: Path, name: str, args: dict[str, Any], preview: str) -> str:
    repo = next((p for p in (work / "payments-api", work / "payments-api.hibernated") if p.is_dir()), None)
    state_file = work / "github_state.json"
    state = json.loads(state_file.read_text()) if state_file.is_file() else {}
    parts: list[str] = []
    if name in ("create_pull_request", "merge_pull_request"):
        num = str(args.get("pull_number") or (re.search(r"'number':\s*(\d+)", preview) or [None, ""])[1])
        pr = (state.get("pulls") or {}).get(num)
        parts.append(f"<h3>Pull request #{html.escape(num)} in the local stub repo</h3><pre>"
                     f"{html.escape(json.dumps(pr, indent=2) if pr else 'not found in github_state.json')}</pre>")
        if pr and repo:
            parts.append(f"<h3>Commits on {html.escape(pr.get('head', ''))}</h3><pre>"
                         f"{html.escape(_git(repo, 'log', '--oneline', '-5', pr.get('head', 'HEAD')))}</pre>")
    elif repo and name == "create_or_update_file":
        sha = re.search(r":\s*([0-9a-f]{7,40})\s*$", preview)
        parts.append(f"<h3>Commit in the local stub repo</h3><pre>"
                     f"{html.escape(_git(repo, 'show', '--stat', sha.group(1)) if sha else 'no commit id in the result')}</pre>")
    elif repo and name == "create_branch" and args.get("branch"):
        parts.append(f"<h3>Branch {html.escape(args['branch'])} in the local stub repo</h3><pre>"
                     f"{html.escape(_git(repo, 'log', '--oneline', '-5', args['branch']))}</pre>")
    if not parts:
        parts.append(f"<h3>Tool result, as recorded</h3><pre>{html.escape(preview[:_PREVIEW_MAX] or '(empty)')}</pre>")
    return "".join(parts)


def _rows_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "<p class=sub>No rows.</p>"
    cols = list(rows[0])
    head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
    body = "".join("<tr>" + "".join(f"<td class=m>{html.escape(str(r.get(c)))}</td>" for c in cols) + "</tr>" for r in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def _sqlite_rows(db: Path, sql: str, args: tuple[Any, ...]) -> list[dict[str, Any]]:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql, args).fetchmany(50)]
    finally:
        conn.close()


def _payments_rows(settings: Settings, work: Path, stub: bool, name: str, args: dict[str, Any]) -> tuple[str, list]:
    order = str(args.get("order_id") or "")
    table = "orders" if name == "get_order" else "refunds"
    where, params = ("WHERE order_id = ?", (order,)) if order else ("", ())
    order_by = "order_id" if table == "orders" else "id"
    sql = f"SELECT * FROM {table} {where} ORDER BY {order_by} LIMIT 50"
    if stub:
        db = work / "payments.sqlite"
        if not db.is_file():
            raise FileNotFoundError(f"{db.name} is gone from the run's work dir")
        return f"payments.{table} (stub SQLite, {db.parent.name})", _sqlite_rows(db, sql, params)
    from cleargate.tools.postgres import PostgresLive

    rows = PostgresLive(settings.database_url).query(f"SELECT * FROM payments.{table} {where.replace('?', '%s')} "
                                                     f"ORDER BY {order_by} LIMIT 50", params)
    return f"payments.{table} (Postgres)", rows if isinstance(rows, list) else []


def _bank_refund(settings: Settings, stub: bool, run_id: str, mode: str, preview: str) -> tuple[str, list]:
    utr = (re.search(r"CLGB[0-9A-F]+", preview) or [None])[0]
    if not stub and utr:
        from cleargate.mcp.seed import DEFAULT_DSN
        from cleargate.tools.postgres import PostgresLive

        rows = PostgresLive(settings.database_url or DEFAULT_DSN).query(
            "SELECT * FROM bank.refunds WHERE utr = %s", (utr,))
        return "bank.refunds (Postgres)", rows if isinstance(rows, list) else []
    ledger = settings.state_dir / "bank" / "ledger.jsonl"
    rows = []
    if ledger.is_file():
        for line in ledger.read_text().splitlines():
            row = json.loads(line) if line.strip() else {}
            if row.get("run_id") == run_id and row.get("mode") == mode and (not utr or row.get("utr") == utr):
                rows.append(row)
    return "bank.refunds read back after the call (stub SQLite, sandbox ledger)", rows


def _outbox(work: Path, file: str, preview: str) -> tuple[str, list]:
    path = work / file
    ts = (re.search(r"'ts':\s*'([\d.]+)'", preview) or [None, None])[1]
    rows = []
    if path.is_file():
        for line in path.read_text().splitlines():
            row = json.loads(line) if line.strip() else {}
            if not ts or row.get("ts") == ts:
                rows.append({k: v for k, v in row.items() if k != "blocks"})
    return f"{file} (stub outbox, {work.parent.name}/{work.name})", rows


def install_outcome_routes(app: FastAPI, settings: Settings, require_approver: Callable[[Request], None],
                           force_stub: bool) -> None:

    @app.get("/api/record/{run_id}/{mode}/line/{seq}")
    def record_line(run_id: str, mode: str, seq: int, request: Request) -> dict[str, Any]:
        require_approver(request)
        path = record_path(settings, run_id, mode)
        header, entry = _line(path, seq)
        return line_summary(path, header, entry)

    @app.get("/api/record/{run_id}/{mode}")
    def record_view(run_id: str, mode: str, request: Request, seq: int = -1) -> HTMLResponse:
        require_approver(request)
        from cleargate.scenario import verify_record

        path = record_path(settings, run_id, mode)
        entries = _lines(path)
        verified = verify_record(path)
        rows = []
        for e in entries:
            p = e.get("payload") or {}
            hit = e.get("seq") == seq
            detail = f"<details{' open' if hit else ''}><summary>line</summary><pre>{html.escape(json.dumps(e, indent=1, default=str)[:_PREVIEW_MAX])}</pre></details>"
            rows.append(f"<tr id=L{e.get('seq')}{' class=hit' if hit else ''}><td class=m>{e.get('seq')}</td>"
                        f"<td>{html.escape(str(p.get('kind', '')))}</td><td class='v-{html.escape(str(p.get('verb', '')))}'>"
                        f"<b>{html.escape(str(p.get('verb', '') or ''))}</b></td><td>{html.escape(str(p.get('agent') or ''))}</td>"
                        f"<td class=m>{html.escape(str(p.get('tool') or ''))}</td><td class=m>{html.escape(str(p.get('rule') or ''))}</td>"
                        f"<td class=m title='{html.escape(str(e.get('hash')))}'>{html.escape(str(e.get('hash', ''))[:16])}…<br>"
                        f"<span class=sub>prev {html.escape(str(e.get('prev_hash', ''))[:8])}…</span></td><td>{detail}</td></tr>")
        ok = verified.startswith("MATCH")
        body = (f"<h1>Signed record {html.escape(path.name)}</h1>"
                f"<div class=sub>{len(entries)} lines, hash-chained and Ed25519-signed · "
                f"<span class={'ok' if ok else 'bad'}>{html.escape(verified)}</span> · verify offline: "
                f"<code>python verify.py records/{html.escape(path.name)}</code></div>"
                f"<table><tr><th>line</th><th>kind</th><th>verb</th><th>agent</th><th>tool</th><th>rule</th>"
                f"<th>hash</th><th></th></tr>{''.join(rows)}</table>"
                + (f"<script>document.getElementById('L{seq}')?.scrollIntoView({{block:'center'}})</script>" if seq >= 0 else ""))
        return _page(path.name, body)

    @app.get("/api/artefact/{run_id}/{mode}/{seq}", response_model=None)
    def artefact(run_id: str, mode: str, seq: int, request: Request) -> HTMLResponse | RedirectResponse:
        require_approver(request)
        path = record_path(settings, run_id, mode)
        header, entry = _line(path, seq)
        p = entry.get("payload") or {}
        tool = str(p.get("tool") or "")
        family, _, name = tool.partition(".")
        args = p.get("args") or {}
        preview = str(p.get("result_preview") or "")
        work = _workdir(settings, path, run_id, mode)
        bank = path.name.startswith("bank-")
        stub_family = {"github": "github", "payments": "payments", "comms": "comms"}.get(family, family)
        stub = force_stub or _is_stub(header, stub_family)
        if p.get("kind") != "call" or not p.get("executed"):
            raise HTTPException(404, f"line {seq} is not an executed tool call")

        if family == "github" and not stub and settings.github_repo:
            url = _github_url(settings.github_repo, name, args, preview)
            if url:
                return RedirectResponse(url, 307)
        if family == "comms" and not stub and name.startswith("post"):
            found = re.search(r"'channel':\s*'([A-Z0-9]+)'.*?'ts':\s*'(\d+)\.(\d+)'", preview)
            if found:
                return RedirectResponse(f"https://slack.com/archives/{found.group(1)}/p{found.group(2)}{found.group(3)}", 307)

        title, content = tool, ""
        try:
            if family == "github" and stub:
                content = _github_stub(work, name, args, preview)
            elif family == "payments" and bank and name == "refund_to_account":
                title, rows = _bank_refund(settings, stub, run_id, mode, preview)
                content = _rows_table(rows)
            elif family == "payments" and not bank and name in ("query_refunds", "get_order", "issue_refund"):
                title, rows = _payments_rows(settings, work, stub, name, args)
                content = _rows_table(rows)
            elif family == "comms" and name.startswith("post"):
                title, rows = _outbox(work, "slack_outbox.jsonl", preview)
                content = _rows_table(rows)
            elif family == "comms" and name == "send_email":
                title, rows = _outbox(work, "email_outbox.jsonl", preview)
                content = _rows_table(rows)
        except Exception as exc:
            content = f"<p class=bad>Could not read the artefact: {html.escape(f'{type(exc).__name__}: {exc}')}</p>"
        if not content:
            content = f"<h3>Tool result, as recorded in the signed line</h3><pre>{html.escape(preview[:_PREVIEW_MAX] or '(empty)')}</pre>"
        tag = ("<span class='tag stub'>stub artefact · local sandbox, not a real system</span>" if stub
               else "<span class='tag live'>live system</span>")
        link = f"/api/record/{run_id}/{mode}?seq={seq}" + (f"&k={request.query_params['k']}" if request.query_params.get("k") else "")
        body = (f"<h1>{html.escape(tool)} <span class='v-{html.escape(str(p.get('verb')))}'>{html.escape(str(p.get('verb')))}</span></h1>"
                f"<div class=sub>{tag} {html.escape(str(p.get('agent') or ''))} · {html.escape(title)}</div>"
                f"<div class=sub>Arguments <code>{html.escape(json.dumps(args)[:400])}</code></div>{content}"
                f"<p class=sub>Decided by {html.escape(str(p.get('source') or ''))} · <a href='{html.escape(link)}#L{seq}'>"
                f"record line {seq}, hash {html.escape(str(entry.get('hash', ''))[:16])}…</a></p>")
        return _page(f"{tool} artefact", body)

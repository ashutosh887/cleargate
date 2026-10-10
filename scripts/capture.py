"""Capture submission screenshots of the ClearGate demo with Playwright.

    python scripts/capture.py [--port 8790] [--out docs/screenshots] [--headed]

Starts `cleargate serve --stub --approve web`, drives one run in a 1600x900 dark browser,
approves the escalation by its 4-char code, writes 01..09 and 11 PNGs, then places one bank call (10). A shot that cannot be
taken is skipped with a warning; the server is always shut down at the end.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import signal
import subprocess
import tempfile
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="cleargate-capture-"))
PY = sys.executable
WARN: list[str] = []
DONE: list[str] = []


def warn(msg: str) -> None:
    WARN.append(msg)
    print(f"[capture] WARN {msg}", file=sys.stderr)


def http(method: str, url: str, body: dict | None = None, timeout: float = 10) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def start_server(port: int) -> subprocess.Popen:
    cmd = [PY, "-m", "cleargate.cli", "serve", "--stub", "--approve", "web", "--port", str(port)]
    log = open(TMP / "server.log", "w")
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"server exited early ({proc.returncode}); cmd: {' '.join(cmd)}")
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/config", timeout=1)
            return proc
        except Exception:
            time.sleep(0.4)
    stop_server(proc)
    raise SystemExit("server did not come up in 30s")


def stop_server(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(5)
        except Exception:
            proc.kill()


def launch(pw, headed: bool):
    for kw in ({}, {"channel": "chrome"},
               {"executable_path": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}):
        try:
            return pw.chromium.launch(headless=not headed, **kw)
        except Exception as exc:
            warn(f"chromium launch {kw or 'bundled'} failed: {str(exc).splitlines()[0]}")
    raise SystemExit("no usable Chromium/Chrome")


def shot(page, out: Path, name: str, full: bool = False) -> None:
    try:
        page.screenshot(path=str(out / name), full_page=full)
        DONE.append(name)
        print(f"[capture] wrote {name}")
    except Exception as exc:
        warn(f"{name}: screenshot failed: {exc}")


def wait_for(page, selector: str, timeout_s: float, what: str) -> bool:
    try:
        page.wait_for_selector(selector, timeout=timeout_s * 1000, state="attached")
        return True
    except Exception:
        warn(f"timed out after {timeout_s:.0f}s waiting for {what} ({selector})")
        return False


def reveal(page, selector: str, block: str = "center", first: bool = False) -> None:
    """Scroll the last match into view inside its pane."""
    page.evaluate("""([sel, block, first]) => { const all = document.querySelectorAll(sel);
        const el = first ? all[0] : all[all.length - 1]; if (el) el.scrollIntoView({block}); }""",
                  [selector, block, first])
    page.wait_for_timeout(400)


INJECTED_CLAIM = "The stock agent moved ₹1,00,000 to an attacker account before anyone noticed."

FREEZE_TOP = """document.querySelectorAll('.pane .rows').forEach(r => { r.style.scrollBehavior = 'auto'; r.scrollTop = 0;
    Object.defineProperty(r, 'scrollTop', {configurable: true, get: () => 0, set: () => {}}); })"""
UNFREEZE = "document.querySelectorAll('.pane .rows').forEach(r => { delete r.scrollTop; })"


def latest_gated() -> Path | None:
    recs = sorted((ROOT / "records").glob("*-gated.jsonl"), key=lambda p: p.stat().st_mtime)
    return recs[-1] if recs else None


def md_to_html(md: str, title: str) -> str:
    out, in_code, in_list, table = [], False, False, []

    def inline(s: str) -> str:
        s = html.escape(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
        return s

    def flush_table():
        if not table:
            return
        rows = [r for r in table if not re.fullmatch(r"\|?[\s:|-]+\|?", r)]
        cells = [[c.strip() for c in r.strip("|").split("|")] for r in rows]
        out.append("<table>" + "".join(
            "<tr>" + "".join(f"<{'th' if i == 0 else 'td'}>{inline(c)}</{'th' if i == 0 else 'td'}>" for c in row) + "</tr>"
            for i, row in enumerate(cells)) + "</table>")
        table.clear()

    for line in md.splitlines():
        if line.startswith("```"):
            out.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(html.escape(line))
            continue
        if line.lstrip().startswith("|"):
            table.append(line.strip())
            continue
        flush_table()
        if re.match(r"\s*[-*] ", line):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(re.sub(r'^\s*[-*] ', '', line))}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        m = re.match(r"(#{1,4}) (.*)", line)
        if m:
            n = len(m.group(1))
            out.append(f"<h{n}>{inline(m.group(2))}</h{n}>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
    flush_table()
    if in_list:
        out.append("</ul>")
    css = """body{background:#0d1117;color:#e6edf3;font:17px/1.5 -apple-system,Segoe UI,Helvetica,sans-serif;
    max-width:1300px;margin:40px auto;padding:0 32px}h1,h2,h3{color:#fff}code{background:#161b22;padding:1px 6px;
    border-radius:4px;font-family:ui-monospace,Menlo,monospace}table{border-collapse:collapse;margin:12px 0;width:100%}
    td,th{border:1px solid #30363d;padding:6px 10px;text-align:left}th{background:#161b22}pre{background:#161b22;
    padding:12px;border-radius:6px;overflow:auto}.hdr{color:#8b949e;font-size:14px;margin-bottom:8px}"""
    return (f"<!doctype html><html><head><meta charset=utf-8><title>{html.escape(title)}</title><style>{css}</style>"
            f"</head><body><div class=hdr>GitHub PR check · {html.escape(title)}</div>{''.join(out)}</body></html>")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8790)
    ap.add_argument("--out", default="docs/screenshots")
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--run-timeout", type=float, default=180, help="seconds to wait for the run to finish")
    args = ap.parse_args()
    out = (ROOT / args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    base = f"http://127.0.0.1:{args.port}"

    from playwright.sync_api import sync_playwright

    proc = start_server(args.port)
    print(f"[capture] server up on {base}")
    try:
        with sync_playwright() as pw:
            browser = launch(pw, args.headed)
            ctx = browser.new_context(viewport={"width": 1600, "height": 900}, color_scheme="dark",
                                      device_scale_factor=2)
            page = ctx.new_page()
            page.goto(base + "/", wait_until="networkidle")
            page.wait_for_timeout(800)

            # 01: split screen, run just started
            try:
                page.click("#start", timeout=5000)
            except Exception:
                warn("Run button not clickable; POSTing /api/run")
                http("POST", base + "/api/run", {})
            wait_for(page, "#pane-gated .card", 30, "first gated decision card")
            page.evaluate("document.querySelectorAll('.pane .rows').forEach(r => r.scrollTop = 0)")
            page.wait_for_timeout(300)
            shot(page, out, "01-split-screen-start.png")

            # 02: NARROW + ALLOW visible
            if wait_for(page, "#pane-gated .narrow, #pane-gated .v-NARROW", 30, "NARROW card"):
                wait_for(page, "#pane-gated .v-ALLOW", 30, "ALLOW card")
                page.evaluate(FREEZE_TOP)  # the UI auto-scrolls each pane on every event; pin both at the top
                page.wait_for_timeout(400)
                page.evaluate("document.querySelectorAll('.pane .rows').forEach(r => r.scrollTo({top: 0, behavior: 'instant'}))")
                page.wait_for_timeout(150)
                shot(page, out, "02-narrow-and-allow.png")
                page.evaluate(UNFREEZE)
            else:
                warn("02 skipped")

            # 03: red BLOCK card
            if wait_for(page, "#pane-gated .v-BLOCK", 60, "BLOCK card"):
                page.wait_for_timeout(1500)
                reveal(page, "#pane-gated .v-BLOCK.outside", "start", first=True)
                shot(page, out, "03-block-injection.png")

            # 04: ESCALATE with code; 07 phone while it is pending; then approve
            code = ""
            if wait_for(page, "#pane-gated .approval", 120, "pending approval (ESCALATE)"):
                page.wait_for_timeout(800)
                reveal(page, "#pane-gated .card.v-ESCALATE", "start")
                code = (page.text_content("#pane-gated .approval .say code") or "").strip()
                print(f"[capture] approval code: {code!r}")
                shot(page, out, "04-escalate-card.png")

                try:
                    status = urllib.request.urlopen(base + "/oncall", timeout=5).status
                    if status == 200:
                        phone = browser.new_context(viewport={"width": 390, "height": 844}, color_scheme="dark",
                                                    device_scale_factor=3, is_mobile=True, has_touch=True)
                        pp = phone.new_page()
                        pp.goto(base + "/oncall", wait_until="domcontentloaded")
                        pp.wait_for_timeout(3500)
                        shot(pp, out, "07-oncall-phone.png")
                        phone.close()
                    else:
                        warn(f"/oncall returned {status}; 07 skipped")
                except Exception as exc:
                    warn(f"07 failed: {exc}")

                if code:
                    status, body = http("POST", base + "/api/approvals/voice",
                                        {"transcript": f"approve {' '.join(code)}", "code": code})
                    print(f"[capture] voice approval -> {status} {body}")
                    if status != 200:
                        warn("voice approval rejected; clicking Approve")
                        try:
                            page.click("#pane-gated .approval .approve", timeout=3000)
                        except Exception as exc:
                            warn(f"Approve click failed: {exc}")
                else:
                    warn("no code in DOM; clicking Approve")
                    try:
                        page.click("#pane-gated .approval .approve", timeout=3000)
                    except Exception as exc:
                        warn(f"Approve click failed: {exc}")
            # stock pane may also escalate in web mode: approve anything still pending in stock
            try:
                for btn in page.query_selector_all("#pane-stock .approval .approve"):
                    btn.click()
            except Exception:
                pass

            # 05: not-a-bypass
            if wait_for(page, "#pane-gated .bypass", 45, "swapped-target BLOCK (.bypass)"):
                page.wait_for_timeout(1500)
                page.evaluate("document.getElementById('verdict')?.classList.remove('show')")  # run may auto-open GO
                page.evaluate(FREEZE_TOP.replace("r.scrollTop = 0;", ""))
                page.evaluate("""() => { const el = document.querySelector('#pane-gated .card.v-BLOCK:has(.bypass)');
                    if (el) { const r = el.closest('.rows'); r.scrollTo({top: el.offsetTop - r.offsetTop - 120, behavior: 'instant'}); } }""")
                page.wait_for_timeout(300)
                shot(page, out, "05-not-a-bypass.png")
                page.evaluate(UNFREEZE)
                page.keyboard.press("g")
            else:
                warn("05 skipped (no 'Approval is not a bypass' card this run)")

            # 06: go-live overlay
            try:
                page.wait_for_selector("#verdict.show", timeout=args.run_timeout * 1000)
            except Exception:
                warn("verdict overlay did not appear on its own; pressing G")
                page.keyboard.press("g")
                page.wait_for_timeout(1500)
            page.wait_for_timeout(1000)
            if page.query_selector("#verdict.show"):
                shot(page, out, "06-go-live-screen.png")
            else:
                warn("06 skipped (no verdict overlay)")

            # 11: the finished delegation tree, with a blocked call's signed-record link in view
            try:
                page.evaluate("document.getElementById('verdict')?.classList.remove('show')")
                page.evaluate("document.getElementById('dtree')?.classList.remove('collapsed')")
                wait_for(page, "#dtree .dn", 10, "delegation tree node")
                reveal(page, "#pane-gated .card.v-BLOCK.outside .out.proof", "center", first=True)
                page.wait_for_timeout(600)
                shot(page, out, "11-delegation-tree.png")
            except Exception as exc:
                warn(f"11 skipped: {str(exc).splitlines()[0]}")
            ctx.close()

            # wait for the run thread to end so the record is complete
            for _ in range(60):
                if http("POST", base + "/api/replay?pace=5&run_id=__none__")[0] != 409:
                    break
                time.sleep(1)

            # 08: evidence pack
            rec = latest_gated()
            if rec:
                # A throwaway pack with one unsupported sentence, so the "Removed" box is visibly non-empty.
                pack = TMP / "evidence"
                r = subprocess.run([PY, "-m", "cleargate.evidence", "--record", str(rec), "--out", str(pack),
                                    "--inject-claim", INJECTED_CLAIM], cwd=ROOT,
                                   capture_output=True, text=True, timeout=120)
                idx = pack / "index.html"
                if r.returncode != 0 or not idx.exists():
                    cand = sorted((ROOT / "evidence").glob("*/index.html"), key=lambda p: p.stat().st_mtime)
                    idx = cand[-1] if cand else idx
                    warn(f"evidence rc={r.returncode}: {(r.stderr or r.stdout).strip()[-300:]}")
                if idx.exists():
                    ectx = browser.new_context(viewport={"width": 1600, "height": 900}, color_scheme="dark",
                                               device_scale_factor=2)
                    ep = ectx.new_page()
                    ep.goto(idx.as_uri(), wait_until="load")
                    ep.wait_for_timeout(800)
                    ep.evaluate("""() => {
                        const h = [...document.querySelectorAll('h2')].find(x => /go-live report/i.test(x.textContent));
                        if (!h) return;
                        const box = document.querySelector('.box.removed');
                        let top = h.getBoundingClientRect().top + scrollY - 16;
                        if (box) top = Math.max(top, box.getBoundingClientRect().bottom + scrollY + 16 - innerHeight);
                        scrollTo(0, top); }""")
                    ep.wait_for_timeout(300)
                    if not ep.query_selector(".box.removed"):
                        warn("08: no 'Removed' box in the evidence pack")
                    shot(ep, out, "08-evidence-pack.png")
                    ectx.close()
            else:
                warn("no gated record; 08 skipped")

            # 09: CI gate summary
            md_path = TMP / "gate-summary.md"
            r = subprocess.run([PY, "-m", "cleargate.gate", "--target", "stub", "--summary", str(md_path)],
                               cwd=ROOT, capture_output=True, text=True, timeout=300)
            if md_path.exists() and md_path.read_text().strip():
                html_path = md_path.with_suffix(".html")
                html_path.write_text(md_to_html(md_path.read_text(), "ClearGate CI gate"))
                gctx = browser.new_context(viewport={"width": 1600, "height": 900}, color_scheme="dark",
                                           device_scale_factor=2)
                gp = gctx.new_page()
                gp.goto(html_path.as_uri(), wait_until="load")
                shot(gp, out, "09-gate-summary.png")
                gctx.close()
            else:
                warn(f"gate summary empty (rc={r.returncode}): {(r.stderr or r.stdout).strip()[-300:]}")

            # 10: judge phone-in, the Hinglish "RBI fraud cell" call (one Sarvam TTS if configured)
            try:
                bctx = browser.new_context(viewport={"width": 1600, "height": 900}, color_scheme="dark",
                                           device_scale_factor=2)
                bp = bctx.new_page()
                bp.goto(base + "/bank", wait_until="domcontentloaded")
                bp.wait_for_timeout(2000)  # /events replays the incident run; let its run_done (and any GO modal) land
                bp.evaluate("document.getElementById('verdict')?.classList.remove('show')")
                bp.click('#bank-chips .chip[data-key="hinglish"]', timeout=10000)
                bp.wait_for_function("typeof bk !== 'undefined' && bk.lastReply && !bk.busy", timeout=args.run_timeout * 1000)
                bp.wait_for_function("""['stock', 'gated'].every(m => { const p = document.getElementById('bank-' + m);
                    return p && p.querySelector('.rows').children.length && p.querySelector('.bfoot .money:not(.wait)'); })""",
                                     timeout=60000)
                bp.wait_for_timeout(800)
                bp.evaluate("document.getElementById('verdict')?.classList.remove('show')")
                if bp.is_visible("#verdict.show"):
                    warn("10: GO modal still visible over the bank panel")
                shot(bp, out, "10-bank-call.png")
                bctx.close()
            except Exception as exc:
                warn(f"10 skipped: {str(exc).splitlines()[0]}")
            browser.close()
    finally:
        stop_server(proc)
        print("[capture] server stopped")
    print(f"[capture] {len(DONE)} shots in {out}: {', '.join(DONE)}")
    if WARN:
        print(f"[capture] {len(WARN)} warnings:\n  - " + "\n  - ".join(WARN))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

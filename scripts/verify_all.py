"""End-to-end verification: live site, repo and CI, code, console, runtime.

Writes submission/verification.md with PASS / FAIL / PARTIAL / NEEDS USER per line and the evidence.
Run through scripts/verify_all.sh. Read-only for product files: outputs that commands rewrite
(docs/coverage.html, submission/live-numbers.md) are restored afterwards.
"""
from __future__ import annotations

import html
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = Path(os.environ.get("CG_PUBLIC", "/private/tmp/claude-501/cg-public"))
SITE = os.environ.get("CG_SITE", "https://trycleargate.vercel.app")
PY = str(ROOT / ".venv/bin/python")
REPO = "ashutosh887/cleargate"
OUT = ROOT / "submission/verification.md"
(ROOT / ".cleargate").mkdir(exist_ok=True)
# inside the repo (gitignored): coverage resolves record paths relative to the repo root
TMP = Path(tempfile.mkdtemp(prefix="verify-", dir=ROOT / ".cleargate"))

rows: list[tuple[str, str, str, str]] = []  # section, check, status, evidence


def add(section: str, check: str, status: str, evidence: str) -> None:
    rows.append((section, check, status, evidence.replace("\n", " ").replace("|", "\\|")[:400]))


def fetch(path: str, data: bytes | None = None, ctype: str | None = None, timeout: int = 30):
    req = urllib.request.Request(SITE + path, data=data, method="POST" if data is not None else "GET")
    req.add_header("User-Agent", "cleargate-verify")
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()
    except Exception as e:  # network
        return 0, {}, str(e).encode()


def sh(cmd: str, timeout: int = 300, env: dict | None = None, cwd: Path = ROOT) -> tuple[int, str]:
    e = {**os.environ, "CLEARGATE_LLM": "scripted", **(env or {})}
    try:
        p = subprocess.run(cmd, shell=True, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout,
                           executable="/bin/zsh")
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired as exc:
        return 124, f"timeout after {timeout}s: {(exc.stdout or '')[-300:] if isinstance(exc.stdout, str) else ''}"


def text_of(page: bytes) -> str:
    s = page.decode("utf-8", "replace")
    s = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", s)
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s)))


# ---------------------------------------------------------------- (a) site
PAGES = ["/", "/how-it-works.html", "/bank-call.html", "/proof.html", "/verify.html", "/built-with.html", "/try.html"]
META = [r"in progress", r"coming at submission", r"goes public", r"goes here", r"\bTODO\b", r"lorem", r"\[N\]",
        r"\[M\]", r"placeholder", r"pending the live", r"\[bracket"]
STALE = [r"\b85 cases\b", r"\b67 of 85\b", r"\blet 67\b", r"\b20,789\b", r"\b26,0\d\d\b"]
CAPS = {"bank voice agent": r"voice", "try a call": r"try a call", "incident team": r"incident",
        "evolving attacker": r"evolv", "policy writer": r"policy writer|least[- ]privilege",
        "coverage / OWASP": r"coverage|owasp", "CI gate / Action": r"github action|\bci\b|pull request",
        "human approval": r"approv", "claim-checked report": r"claim", "signed record / verify": r"signed record|verify"}


def site_checks() -> None:
    S = "a. Site"
    pages: dict[str, bytes] = {}
    for p in PAGES:
        code, _, body = fetch(p)
        pages[p] = body if code == 200 else b""
        add(S, f"page {p} returns 200", "PASS" if code == 200 else "FAIL", f"HTTP {code}")
    home = pages.get("/", b"").decode("utf-8", "replace")
    nav_links = set(re.findall(r'<nav[^>]*>(.*?)</nav>', home, re.S))
    add(S, "7+ pages linked from the nav", "PASS" if sum(len(re.findall(r'href="/[^"#]*\.html"', n)) for n in nav_links) >= 6 else "FAIL",
        f"nav hrefs: {sorted(set(re.findall(r'href=\"(/[^\"]*)\"', ' '.join(nav_links))))}")
    _, _, css = fetch("/styles.css")
    css_s = css.decode("utf-8", "replace")
    sticky = re.search(r"\.bar[^{]*\{[^}]*position:\s*sticky", css_s) or re.search(r"header[^{]*\{[^}]*position:\s*sticky", css_s)
    add(S, "sticky nav (position: sticky on the header)", "PASS" if sticky else ("PARTIAL" if "sticky" in css_s else "FAIL"),
        "found in styles.css" if sticky else ("'sticky' appears but not on the header rule" if "sticky" in css_s else "no position: sticky in styles.css"))
    header = (re.search(r"<header.*?</header>", home, re.S) or [""])[0] if home else ""
    gh_icon = re.search(r'<a[^>]+href="https://github\.com/ashutosh887/cleargate"[^>]*>.*?<svg', header, re.S)
    add(S, "GitHub icon in the navbar", "PASS" if gh_icon else "FAIL", "svg link in <header>" if gh_icon else "no github svg link inside <header>")
    try_btn = re.search(r'href="/try\.html"', header)
    add(S, "'Try a call' in the navbar", "PASS" if try_btn else "FAIL", "/try.html in header" if try_btn else "missing")
    footer = (re.search(r"<footer.*?</footer>", home, re.S) or [""])[0] if home else ""
    cols = [w for w in ("Product", "Proof", "Code") if re.search(rf">\s*{w}\s*<", footer)]
    add(S, "footer has columns (Product / Proof / Code)", "PASS" if len(cols) == 3 else ("PARTIAL" if cols else "FAIL"),
        f"headings found: {cols or 'none'}")
    home_t = text_of(pages.get("/", b"")).lower()
    missing = [k for k, rx in CAPS.items() if not re.search(rx, home_t)]
    add(S, "home page names every capability", "PASS" if not missing else "FAIL", f"missing: {missing}" if missing else "all 10 found")
    gen = re.search(r"any (ai )?agent|for (all|every) agent|ai agents? that (take|move|change)", home_t)
    add(S, "'any agent' positioning on home", "PASS" if gen else "FAIL", gen.group(0) if gen else "no generic positioning phrase")
    uses = re.search(r"use it for|built for|what you (can|get)", home_t)
    add(S, "'Use it for' / 'What you get' section on home", "PASS" if uses else "FAIL", uses.group(0) if uses else "not found")
    hero = text_of(re.search(rb"<main.*?</section>", pages.get("/", b""), re.S).group(0) if re.search(rb"<main.*?</section>", pages.get("/", b""), re.S) else b"")
    add(S, "hero is short (< 90 words before the first section ends)", "PASS" if len(hero.split()) < 90 else "FAIL", f"{len(hero.split())} words")
    for label, pats in (("no meta/process lines", META), ("no stale numbers (85/67/old evolve totals)", STALE)):
        hits = []
        for p, body in pages.items():
            t = text_of(body)
            hits += [f"{p}: '{m.group(0)}'" for rx in pats for m in [re.search(rx, t, re.I)] if m]
        add(S, label, "PASS" if not hits else "FAIL", "; ".join(hits) or "none on 7 pages")
    num = (ROOT / "submission/numbers.md").read_text() if (ROOT / "submission/numbers.md").exists() else ""
    canon = ["2,22,840", "15,580", "49", "11"]
    missing_canon = [c for c in canon[:2] if c not in text_of(pages.get("/", b"") + pages.get("/bank-call.html", b""))]
    add(S, "canon rupee numbers on home/bank-call (₹2,22,840, ₹15,580)", "PASS" if not missing_canon else "FAIL",
        f"missing {missing_canon}" if missing_canon else "present" + ("" if num else " (numbers.md not found)"))
    _, _, live_llms = fetch("/llms.txt")
    a, b = (ROOT / "llms.txt").read_bytes(), (ROOT / "site/llms.txt").read_bytes()
    add(S, "llms.txt: root == site/llms.txt == live", "PASS" if a == b == live_llms else "FAIL",
        f"root==site {a == b}, site==live {b == live_llms}")
    for f, kind in (("/favicon.ico", "image"), ("/assets/favicon.svg", "svg"), ("/assets/apple-touch-icon.png", "image")):
        code, hd, _ = fetch(f)
        add(S, f"favicon {f}", "PASS" if code == 200 else "FAIL", f"HTTP {code} {hd.get('content-type', '') if hd else ''}")
    bank = pages.get("/bank-call.html", b"").decode("utf-8", "replace")
    srcs = re.findall(r'src="([^"]+\.(?:m4a|wav|mp3))"', bank)
    if not srcs:
        add(S, "caller audio on bank-call page", "FAIL", "no audio sources")
    for s in srcs:
        code, hd, body = fetch(s)
        ct = hd.get("content-type", "") if hd else ""
        ok = code == 200 and ct.startswith("audio/") and len(body) > 10000
        add(S, f"audio {s}", "PASS" if ok else "FAIL", f"HTTP {code} {ct} {len(body)} bytes")
    # /api/call for every preset on the live try page
    tryp = pages.get("/try.html", b"").decode("utf-8", "replace")
    presets = [html.unescape(t) for t in re.findall(r'data-text="([^"]+)"', tryp)]
    add(S, "try page has presets", "PASS" if len(presets) >= 5 else "FAIL", f"{len(presets)} presets")
    funny = re.compile(r"nephew|cat |diwali|canteen|supervisor", re.I)
    add(S, "funny professional presets present", "PASS" if any(funny.search(p) for p in presets) else "FAIL",
        f"{sum(bool(funny.search(p)) for p in presets)} found")

    def one(text: str):
        code, _, body = fetch("/api/call", json.dumps({"text": text}).encode(), "application/json")
        return text, code, body
    with ThreadPoolExecutor(6) as ex:
        for text, code, body in ex.map(one, presets):
            short = text[:60]
            if code != 200:
                add(S, f"/api/call: {short}", "FAIL", f"HTTP {code} {body[:120]!r}")
                continue
            d = json.loads(body)
            st, ga = d["panes"]["stock"]["counts"], d["panes"]["gated"]["counts"]
            sm, gm = st.get("attack_money_moved_inr", 0), ga.get("attack_money_moved_inr", 0)
            ver = d["panes"]["gated"].get("verified", "")
            if st.get("attack_attempts", 0) == 0:
                status = "PASS" if gm == 0 else "FAIL"
                ev = f"legit call: stock moved off file {sm}, gated {gm}; gated verify {ver[:30]}"
            else:
                status = "PASS" if sm > 0 and gm == 0 else "FAIL"
                ev = f"stock moved ₹{sm}, gated ₹{gm}; gated verify {str(ver)[:30]}"
            add(S, f"/api/call: {short}", status, ev)
    code, _, body = fetch("/api/voice?phone=%2B91-98123-45678", b"RIFF\x00\x00\x00\x00WAVE", "audio/wav")
    if code == 503:
        add(S, "/api/voice responds", "NEEDS USER", f"503 voice off (SARVAM_API_KEY not on Vercel; user decision): {body[:90]!r}")
    elif code in (200, 400, 413, 415, 422):
        add(S, "/api/voice responds", "PASS", f"HTTP {code} (function alive) {body[:90]!r}")
    else:
        add(S, "/api/voice responds", "FAIL", f"HTTP {code} {body[:120]!r}")
    has_voice = 'id="voice"' in tryp and "/voice.js" in tryp
    add(S, "try page loads voice.js with #voice slot", "PASS" if has_voice else "FAIL", "present" if has_voice else "missing slot or script")


# ---------------------------------------------------------------- (b) repo
SECRET = re.compile(r"(^|[^a-zA-Z])(sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|"
                    r"github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{30,}|xox[bp]-[0-9A-Za-z-]{20,})")
CONV = re.compile(r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9._/-]+\))?!?: \S")


def repo_checks() -> None:
    S = "b. Repo and CI"
    gh = f"GH_TOKEN=$(gh auth token -u ashutosh887) gh"
    _, remote = sh(f"git -C {PUBLIC} ls-remote origin main", 30)
    head = remote.split()[0] if remote.strip() else ""
    rc, out = sh(f"{gh} run list -R {REPO} -b main -L 12 --json headSha,status,conclusion,name,displayTitle", 60)
    try:
        runs = [r for r in json.loads(out) if r["headSha"] == head]
    except Exception:
        runs = []
    if not runs:
        add(S, "CI on latest main commit", "FAIL", f"no runs for {head[:7]} ({out[:120]})")
    else:
        concl = {r["name"] + ":" + (r["conclusion"] or r["status"]) for r in runs}
        ok = all(r["conclusion"] in ("success", "skipped") for r in runs)
        pending = any(r["status"] != "completed" for r in runs)
        add(S, "CI on latest main commit", "PASS" if ok else ("PARTIAL" if pending else "FAIL"),
            f"{head[:7]} {runs[0]['displayTitle'][:50]}: {sorted(concl)}")
    rc, out = sh(f"{gh} pr view 3 -R {REPO} --json state,statusCheckRollup,title", 60)
    try:
        pr = json.loads(out)
        checks = [(c.get("name"), c.get("conclusion") or c.get("state")) for c in pr["statusCheckRollup"]]
        red = any(str(c[1]).upper() == "FAILURE" for c in checks)
        add(S, "PR #3 is red (gate catches the loosened policy)", "PASS" if red else "FAIL", f"{pr['state']}: {checks}")
    except Exception:
        add(S, "PR #3 is red", "FAIL", out[:200])
    files = subprocess.run(["git", "-C", str(PUBLIC), "ls-files"], capture_output=True, text=True).stdout.split()
    readme = (PUBLIC / "README.md").read_text()
    bad = []
    for link in re.findall(r"\]\(([^)\s]+)\)", readme):
        if link.startswith(("http", "#", "mailto:")):
            continue
        p = link.split("#")[0]
        if p and not (PUBLIC / p).exists():
            bad.append(link)
    add(S, "README relative links resolve", "PASS" if not bad else "FAIL", f"broken: {bad}" if bad else "all resolve")
    leaks, big = [], []
    for f in files:
        fp = PUBLIC / f
        if not fp.is_file():
            continue
        size = fp.stat().st_size
        if size > 1_000_000:
            big.append(f"{f} ({size // 1024} KB)")
        if size < 2_000_000:
            try:
                if SECRET.search(fp.read_text(errors="ignore")):
                    leaks.append(f)
            except Exception:
                pass
    add(S, "no secrets in tracked files", "PASS" if not leaks else "FAIL", f"matches in {leaks}" if leaks else f"{len(files)} files scanned")
    add(S, "no bloat (tracked files > 1 MB)", "PASS" if not big else "PARTIAL", "; ".join(big) or "none")
    log = subprocess.run(["git", "-C", str(PUBLIC), "log", "-40", "--format=%s%x1f%b%x1e"], capture_output=True, text=True).stdout
    subj = [e.split("\x1f") for e in log.strip("\x1e\n").split("\x1e") if e.strip()]
    noncon = [s.strip() for s, _ in subj if not CONV.match(s.strip())]
    vague = [s.strip() for s, _ in subj if re.search(r"\bpolish\b|\bfinal\b|say what|let visitors", s)]
    trailers = [s.strip() for s, b in subj if re.search(r"co-authored-by|signed-off-by", b, re.I)]
    add(S, "commit subjects conventional (last 40)", "PASS" if not noncon else "FAIL", f"non-conforming: {noncon}" if noncon else "40/40")
    add(S, "no vague/chatty subjects (last 40)", "PASS" if not vague else "PARTIAL", f"{vague}" if vague else "none")
    add(S, "no commit trailers (last 40)", "PASS" if not trailers else "FAIL", f"{trailers}" if trailers else "none")
    src_vs_pub = [f for f in files if (ROOT / f).is_file() and (ROOT / f).read_bytes() != (PUBLIC / f).read_bytes()]
    add(S, "source checkout == pushed tree (uncommitted lane work)", "PASS" if not src_vs_pub else "PARTIAL",
        f"{len(src_vs_pub)} differ: {src_vs_pub[:12]}" if src_vs_pub else "identical")


# ---------------------------------------------------------------- (c) code
def code_checks() -> None:
    S = "c. Code"
    protect = [ROOT / "docs/coverage.html", ROOT / "submission/live-numbers.md"]
    saved = {p: p.read_bytes() for p in protect if p.exists()}
    rc, out = sh(f"{PY} -m compileall -q cleargate verify.py scripts", 120)
    add(S, "compileall", "PASS" if rc == 0 else "FAIL", out[-200:] or "clean")
    jobs = {
        "cleargate check --stub": ("check --stub --quiet", {}),
        "cleargate gate --target stub": ("gate --target stub", {}),
        "cleargate bank --demo all --stub": ("bank --demo all --stub", {}),
        "PAYEE_CHECK=off cleargate bank --campaign --stub --seed 7": ("bank --campaign --stub --seed 7", {"PAYEE_CHECK": "off"}),
        "cleargate coverage": ("coverage", {}),
    }

    def run(item):
        label, (args, env) = item
        d = TMP / re.sub(r"\W+", "-", label)
        d.mkdir(parents=True, exist_ok=True)
        rc, out = sh(f"{PY} -m cleargate.cli {args}", 300,
                     {**env, "CLEARGATE_RECORDS_DIR": str(d / "records"), "CLEARGATE_STATE_DIR": str(d / "state")})
        return label, rc, out, d

    with ThreadPoolExecutor(6) as ex:
        futs = [ex.submit(run, i) for i in jobs.items()]
        futs.append(ex.submit(lambda: ("scripts/live_all.sh --stub",) + sh("scripts/live_all.sh --stub", 300) + (None,)))
        results = [f.result() for f in futs]
    for label, rc, out, d in results:
        key = ""
        for rx in (r"GATED.*?→\s*\S+", r"(\d+) of (\d+) attacks reached", r"MATCH[^\n]{0,60}", r"gated[^\n]{0,80}₹[\d,]+",
                   r"steps? .*exit", r"PASS[^\n]{0,60}"):
            m = re.search(rx, out)
            if m:
                key = m.group(0)
                break
        mism = "MISMATCH" in out
        add(S, label, "PASS" if rc == 0 and not mism else "FAIL", f"exit {rc}; {key or out.strip()[-160:]}")
    recs = [r for r in TMP.rglob("*.jsonl") if r.parent.name == "records"]
    fails = []
    for r in recs:
        rc, out = sh(f"{PY} verify.py {r}", 60)
        if rc != 0 or "MATCH" not in out or "MISMATCH" in out:
            fails.append(f"{r.name}: {out.strip()[-80:]}")
    add(S, f"verify.py on every new record ({len(recs)})", "PASS" if recs and not fails else "FAIL",
        "; ".join(fails[:5]) or f"{len(recs)} MATCH")
    # durable approval: hibernate in one process, approve + resume in fresh processes
    d = TMP / "durable"
    env = {"CLEARGATE_RECORDS_DIR": str(d / "records"), "CLEARGATE_STATE_DIR": str(d / "state")}
    rc, out = sh(f"{PY} -m cleargate.cli check --stub --durable --mode gated --quiet", 180, env)
    rec = re.search(r"receipt ([0-9a-f]+)", out)
    code = re.search(r"approval code[^:]*:\s*(\S+)", out)
    if rec and code:
        rc2, out2 = sh(f"{PY} -m cleargate.cli approve {rec.group(1)} --code {code.group(1)}", 60, env)
        rc3, out3 = sh(f"{PY} -m cleargate.cli resume {rec.group(1)} --quiet", 180, env)
        ok = rc2 == 0 and rc3 == 0 and "MATCH" in out3
        add(S, "durable approval survives process exit (hibernate → approve → resume)", "PASS" if ok else "FAIL",
            f"receipt {rec.group(1)[:12]}; approve exit {rc2}; resume exit {rc3}; {re.search(r'MATCH[^\n]{0,40}', out3).group(0) if 'MATCH' in out3 else out3.strip()[-120:]}")
    else:
        add(S, "durable approval survives process exit", "FAIL", f"no hibernation receipt; exit {rc}; {out.strip()[-160:]}")
    for p, b in saved.items():
        p.write_bytes(b)


# ---------------------------------------------------------------- (d) console
def console_checks() -> None:
    S = "d. Console"
    port = 8761
    env = {**os.environ, "CLEARGATE_LLM": "scripted", "CLEARGATE_RECORDS_DIR": str(TMP / "serve/records"),
           "CLEARGATE_STATE_DIR": str(TMP / "serve/state")}
    log = open(TMP / "serve.log", "w")
    proc = subprocess.Popen([PY, "-m", "cleargate.cli", "serve", "--stub", "--port", str(port)], cwd=ROOT, env=env,
                            stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(60):
            try:
                urllib.request.urlopen(base + "/", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
        key = (re.search(r"\?k=([\w-]+)", (TMP / "serve.log").read_text()) or [None, ""])[1]
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch()
            for path in ("/", f"/bank?k={key}", f"/oncall?k={key}"):
                pg = b.new_page(viewport={"width": 1440, "height": 900})
                errs: list[str] = []
                pg.on("pageerror", lambda e: errs.append(str(e)))
                try:
                    r = pg.goto(base + path, wait_until="networkidle", timeout=20000)
                    pg.wait_for_timeout(800)
                    body = pg.inner_text("body")
                    add(S, f"console {path.split('?')[0]} loads", "PASS" if r and r.ok and not errs else "FAIL",
                        f"HTTP {r.status if r else '?'}; page errors: {errs[:2] or 'none'}")
                    if path == "/":
                        pg.screenshot(path=str(TMP / "console.png"))
                        kill = re.search(r"end task|kill switch", body, re.I) or pg.query_selector("[data-kill], #kill, button:has-text('End task')")
                        add(S, "kill switch ('End task') on console", "PASS" if kill else "FAIL", "found" if kill else "not on page")
                        try:
                            pg.keyboard.press("r")
                            pg.wait_for_timeout(6000)
                            body = pg.inner_text("body")
                        except Exception:
                            pass
                        lat = re.search(r"p50[^\n]{0,30}ms|\d+(\.\d+)?\s?ms\b", body)
                        add(S, "latency (ms) shown on console after a replay", "PASS" if lat else "FAIL", lat.group(0) if lat else "no ms figure")
                except Exception as e:
                    add(S, f"console {path.split('?')[0]} loads", "FAIL", str(e)[:200])
                pg.close()
            b.close()
    finally:
        os.killpg(proc.pid, signal.SIGTERM)
        log.close()


# ---------------------------------------------------------------- (e) runtime
def runtime_checks() -> None:
    S = "e. AgntID runtime"
    rc, out = sh(f"{PY} scripts/runtime_proof.py", 120)
    todo = [l.strip() for l in out.splitlines() if l.strip().startswith("[ ]")]
    if rc == 0 and "ALL PASS" in out:
        add(S, "runtime connected and wired (runtime_proof)", "PASS", "ALL PASS")
    else:
        add(S, "runtime connected and wired (runtime_proof)", "NEEDS USER",
            f"exit {rc}; {len(todo)} portal steps open; next: {todo[0] if todo else out.strip()[-150:]}")
    ln = ROOT / "submission/live-numbers.md"
    live = ln.exists() and "STUB DRY RUN" not in ln.read_text()[:400]
    add(S, "live numbers measured through AgntID (live_all.sh)", "PASS" if live else "NEEDS USER",
        "submission/live-numbers.md is a live run" if live else "only the stub dry run so far")


# ---------------------------------------------------------------- plan-vs-live (recorded statuses)
def plan_rows() -> list[str]:
    p = ROOT / "submission/plan-vs-live.md"
    if not p.exists():
        return ["plan-vs-live.md not found"]
    out = []
    for line in p.read_text().splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or set(cells[0]) <= set("-") or cells[0] in ("#", "Item"):
            continue
        item, status = (cells[1], cells[2]) if cells[0].isdigit() else (cells[0], cells[1])
        tag = ("PASS" if status.startswith("LIVE") else "NEEDS USER" if status.startswith("NEEDS USER")
               else "PARTIAL" if status.startswith("PARTIAL") else "FAIL" if status.startswith("NOT DONE")
               else status.split()[0] if status else "?")
        out.append(f"| {item[:90]} | {tag} | {status[:60]} |")
    return out


def main() -> int:
    t0 = time.time()
    with ThreadPoolExecutor(5) as ex:
        fs = [ex.submit(f) for f in (site_checks, repo_checks, code_checks, runtime_checks)]
        for f in fs:
            try:
                f.result()
            except Exception as e:
                add("z. Verifier", "a check group crashed", "FAIL", repr(e))
    try:
        console_checks()
    except Exception as e:
        add("d. Console", "console smoke", "FAIL", repr(e)[:200])
    order = {"PASS": 0}
    counts: dict[str, int] = {}
    for r in rows:
        counts[r[2]] = counts.get(r[2], 0) + 1
    stamp = time.strftime("%H:%M IST, %a %Y-%m-%d")
    lines = [f"# ClearGate verification ({stamp})", "",
             f"`scripts/verify_all.sh` in {time.time() - t0:.0f}s against {SITE}, {PUBLIC} and the source checkout. "
             "Private file. Statuses: PASS, FAIL, PARTIAL, NEEDS USER.", "",
             "**Totals:** " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda kv: order.get(kv[0], 1))), "",
             "## Failing or open", "", "| Section | Check | Status | Evidence |", "|---|---|---|---|"]
    lines += [f"| {s} | {c} | {st} | {e} |" for s, c, st, e in sorted(rows) if st != "PASS"]
    lines += ["", "## All checks", "", "| Section | Check | Status | Evidence |", "|---|---|---|---|"]
    lines += [f"| {s} | {c} | {st} | {e} |" for s, c, st, e in sorted(rows, key=lambda r: r[0])]
    lines += ["", "## Plan items (status recorded in submission/plan-vs-live.md; automated checks above override)", "",
              "| Item | Status | Recorded as |", "|---|---|---|"] + plan_rows()
    OUT.write_text("\n".join(lines) + "\n")
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"wrote {OUT.relative_to(ROOT)}: " + ", ".join(f"{k} {v}" for k, v in counts.items()) + f" in {time.time() - t0:.0f}s")
    return 0 if counts.get("FAIL", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

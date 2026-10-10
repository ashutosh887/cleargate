"""Shared look for generated report pages (coverage, evolution): the site's fonts, tokens and header."""
from __future__ import annotations

from html import escape

SITE = "https://trycleargate.vercel.app"
REPO = "https://github.com/ashutosh887/cleargate"

NAV = (("How it works", "/how-it-works.html"), ("The bank call", "/bank-call.html"), ("Proof", "/proof.html"),
       ("Verify", "/verify.html"), ("Built with", "/built-with.html"), ("Try a call", "/try.html"))

GITHUB_ICON = ('<svg viewBox="0 0 16 16" width="20" height="20" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 '
               '3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23'
               '-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78'
               '-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 '
               '1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25'
               '.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>')

# Same tokens and type scale as site/styles.css.
CSS = """
:root{--sans:"Archivo",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
--mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
--paper:#e9edf3;--paper-hi:#f7f9fc;--rule:#c3cbd8;--ink:#0f1522;--ink-2:#172030;--text:#0f1522;--muted:#4a576c;
--muted-ink:#a3afc2;--allow:#138a5b;--narrow:#1f6fd1;--block:#d42f2f;--escalate:#ffb547;--escalate-dk:#9a5b00;
--allow-ink:#3ddc97;--block-ink:#ff6b6b;--wide:1080px}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--text);font:400 16px/1.55 var(--sans)}
a{color:inherit;text-underline-offset:3px}
code{font-family:var(--mono);font-size:.86em;background:rgba(15,21,34,.07);padding:.05em .3em;border-radius:3px;overflow-wrap:anywhere}
.wrap{max-width:var(--wide);margin:0 auto;padding:0 32px}
.bar{position:sticky;top:0;z-index:10;background:var(--ink);color:#eef1f6}
.bar .wrap{display:flex;align-items:center;justify-content:space-between;gap:24px;min-height:60px}
.brand{display:inline-flex;align-items:center;gap:10px;font-weight:800;font-size:22px;text-decoration:none;letter-spacing:-.02em}
.brand .mark{font:800 13px/1 var(--sans);letter-spacing:.04em;color:var(--escalate);border:2.5px solid currentColor;border-radius:4px;padding:4px 5px 3px;rotate:-4deg}
.bar nav{display:flex;align-items:center;gap:20px;overflow-x:auto}
.bar nav a{font-size:15px;color:var(--muted-ink);text-decoration:none;white-space:nowrap}
.bar nav a:hover{color:#fff}
.bar nav a.gh{display:inline-flex;color:#eef1f6}
.framed .bar{display:none}
main{padding:44px 0 72px}
h1{font-weight:800;letter-spacing:-.02em;font-size:clamp(32px,4.4vw,48px);line-height:1.05;margin:0 0 10px}
h2{font-weight:800;letter-spacing:-.02em;font-size:26px;line-height:1.15;margin:48px 0 14px}
h3{font-weight:800;font-size:19px;margin:0 0 10px}
.sub{color:var(--muted);font-size:15px;max-width:72ch}
.chips{display:flex;flex-wrap:wrap;gap:10px;margin:22px 0}
.chip{font:600 15px/1.2 var(--mono);border:2px solid var(--ink);border-radius:3px;padding:9px 12px;background:var(--paper-hi)}
.chip.bad{border-color:var(--block);color:var(--block)} .chip.good{border-color:var(--allow);color:var(--allow)}
.chip.warn{border-color:var(--escalate-dk);color:var(--escalate-dk)}
.banner{border-left:4px solid var(--escalate);background:var(--paper-hi);padding:10px 14px;font-size:15px;max-width:72ch}
.scroll{overflow-x:auto}
footer.fine{color:var(--muted);font-size:14px;margin-top:40px;padding-top:16px;border-top:2px solid var(--ink);max-width:72ch}
@media (max-width:640px){.wrap{padding:0 18px} .bar nav a:not(.gh){display:none} main{padding:28px 0 56px}}
"""


def head(title: str, css: str) -> str:
    return (f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>{escape(title)}</title>\n'
            '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            '<link rel="icon" href="/favicon.ico" sizes="any">\n'
            '<link rel="preconnect" href="https://fonts.googleapis.com">\n'
            '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
            '<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;600;800&amp;family=IBM+Plex+Mono:wght@400;600'
            '&amp;display=swap" rel="stylesheet">\n'
            '<script>if(window.self!==window.top)document.documentElement.classList.add("framed")</script>\n'
            f'<style>{CSS}{css}</style></head>')


def header() -> str:
    links = "".join(f'<a href="{SITE}{href}">{escape(name)}</a>' for name, href in NAV)
    return (f'<header class="bar"><div class="wrap"><a class="brand" href="{SITE}/"><span class="mark" aria-hidden="true">CG'
            f'</span> ClearGate</a><nav aria-label="Pages">{links}<a class="gh" href="{REPO}" aria-label="ClearGate on GitHub">'
            f'{GITHUB_ICON}</a></nav></div></header>')

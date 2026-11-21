"""Build the public web version of the hackathon deck.

  python scripts/build_slides.py   ->  docs/slides/index.html  (served at <pages-url>/slides/)

Sources live in slides/src (deck.json, deck.css, slides/<id>.html), exported from the
presentation tool. This script stitches them into one self-contained page with keyboard
navigation, scales the 1920x1080 slides to the window, and maps the deck's uploaded
images and custom elements to plain HTML.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "slides" / "src"
OUT = ROOT / "docs" / "slides" / "index.html"

# uploaded deck images -> the same charts exported to docs/charts
BLOBS = {
    "0d0e18d9bd41c72f7b04f62e1d900820": "../charts/2-3_takeover_fingerprint.png",
    "7a2a7a21dc594655821ecd9258d9def5": "../charts/3-3_tradeoff_curve.png",
    "685284cbba5b762cf9166abcf68bb6c3": "../charts/4-2_redteam_heatmap.png",
    "914ae8a282c2f0835938453d3b321a3a": "../charts/3-2_decision_matrix.png",
}
ICONS = {"Warning": "⚠", "Users": "👥", "Chat": "💬"}

VIEWER_CSS = """
html, body { margin: 0; height: 100%; background: #0B1220; overflow: hidden; }
#stage { position: fixed; inset: 0; display: flex; align-items: center; justify-content: center; }
#deck { width: 1920px; height: 1080px; position: relative; transform-origin: center center; flex: none; }
#deck > section { position: absolute; inset: 0; width: 1920px; height: 1080px; display: none !important; overflow: hidden; }
#deck > section.on { display: flex !important; }
#deck > section aside { display: none; }
.x-conn { align-self: center; width: 56px; text-align: center; font-size: 40px; font-weight: 700; color: var(--orange); flex: none; }
.x-icon { font-size: 48px; line-height: 1; }
#bar { position: fixed; left: 0; right: 0; bottom: 0; display: flex; gap: 10px; align-items: center; justify-content: center;
  padding: 8px; font: 14px system-ui, sans-serif; color: #C3CDDA; background: rgba(11,18,32,.75); z-index: 5; }
#bar button, #bar a { background: #16263D; color: #F1EFEA; border: 1px solid #2C3F5C; border-radius: 8px; padding: 6px 12px;
  font: inherit; cursor: pointer; text-decoration: none; }
#notes { position: fixed; left: 50%; transform: translateX(-50%); bottom: 52px; width: min(900px, 94vw); max-height: 34vh; overflow: auto;
  background: #F5F3EE; color: #14213D; border-radius: 12px; padding: 14px 18px; font: 15px/1.5 system-ui, sans-serif;
  display: none; z-index: 6; box-shadow: 0 8px 30px rgba(0,0,0,.4); }
#notes.show { display: block; }
@media (prefers-reduced-motion: reduce) { .rise, .fade { animation: none !important; } }
"""

VIEWER_JS = """
const slides = [...document.querySelectorAll('#deck > section')];
const deck = document.getElementById('deck'), notes = document.getElementById('notes'), count = document.getElementById('count');
let i = 0;
function fit() { const s = Math.min(innerWidth / 1920, (innerHeight - 48) / 1080); deck.style.transform = `scale(${s})`; }
function show(n) {
  i = Math.max(0, Math.min(slides.length - 1, n));
  slides.forEach((s, k) => s.classList.toggle('on', k === i));
  const a = slides[i].querySelector('aside');
  notes.textContent = a ? a.textContent : 'No speaker notes for this slide.';
  count.textContent = `${i + 1} / ${slides.length}`;
  history.replaceState(null, '', '#' + (i + 1));
}
addEventListener('resize', fit);
addEventListener('keydown', e => {
  if (['ArrowRight', 'PageDown', ' '].includes(e.key)) { e.preventDefault(); show(i + 1); }
  else if (['ArrowLeft', 'PageUp'].includes(e.key)) { e.preventDefault(); show(i - 1); }
  else if (e.key === 'Home') show(0);
  else if (e.key === 'End') show(slides.length - 1);
  else if (e.key.toLowerCase() === 'n') notes.classList.toggle('show');
  else if (e.key.toLowerCase() === 'f') document.documentElement.requestFullscreen?.();
});
document.getElementById('prev').onclick = () => show(i - 1);
document.getElementById('next').onclick = () => show(i + 1);
document.getElementById('nbtn').onclick = () => notes.classList.toggle('show');
document.getElementById('stage').addEventListener('click', e => { if (!e.target.closest('a')) show(i + (e.clientX < innerWidth / 3 ? -1 : 1)); });
fit(); show((parseInt(location.hash.slice(1)) || 1) - 1);
"""


def convert(section: str) -> str:
    for blob, path in BLOBS.items():
        section = section.replace(f"/_blob/{blob}", path)
    section = re.sub(r"<x-connector[^>]*></x-connector>", '<div class="x-conn" aria-hidden="true">→</div>', section)
    section = re.sub(r'<x-icon name="(\w+)" style="([^"]*)"></x-icon>',
                     lambda m: f'<div class="x-icon" style="{m.group(2)}" aria-hidden="true">{ICONS.get(m.group(1), "•")}</div>',
                     section)
    return section


def main():
    idx = json.loads((SRC / "deck.json").read_text(encoding="utf-8"))
    css = (SRC / "deck.css").read_text(encoding="utf-8")
    href = next(iter(idx["faces"].values()))["href"]
    body = "\n".join(convert((SRC / "slides" / f"{sid}.html").read_text(encoding="utf-8")) for sid in idx["order"])
    title = html.escape(idx["title"])
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="Sentinel hackathon presentation: AI account-takeover detection that can't be talked out of a verdict.">
<link rel="stylesheet" href="{href}">
<style>{css}</style><style>{VIEWER_CSS}</style></head>
<body>
<div id="stage"><div id="deck">
{body}
</div></div>
<div id="notes" aria-live="polite"></div>
<div id="bar"><button id="prev" aria-label="Previous slide">←</button><span id="count"></span>
<button id="next" aria-label="Next slide">→</button><button id="nbtn">Speaker notes (N)</button>
<a href="../">Live demo</a><a href="https://github.com/pengbaier/sentinel-ato">GitHub</a>
<span style="opacity:.7">← → keys · F fullscreen</span></div>
<script>{VIEWER_JS}</script>
</body></html>
"""
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(page, encoding="utf-8")
    print(f"wrote {OUT} ({len(idx['order'])} slides)")

    # Print layout: every slide on its own 1920x1080 page, no animation, for PDF export.
    print_css = """
@page { size: 1920px 1080px; margin: 0; }
html, body { margin: 0; background: #fff; }
body > section { width: 1920px; height: 1080px; overflow: hidden; break-after: page; page-break-after: always; }
body > section aside { display: none; }
.x-conn { align-self: center; width: 56px; text-align: center; font-size: 40px; font-weight: 700; color: var(--orange); flex: none; }
.x-icon { font-size: 48px; line-height: 1; }
*, *::before, *::after { animation: none !important; transition: none !important; }
* { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
"""
    printable = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<link rel="stylesheet" href="{href}">
<style>{css}</style><style>{print_css}</style></head>
<body>
{body}
</body></html>
"""
    (OUT.parent / "print.html").write_text(printable, encoding="utf-8")
    print(f"wrote {OUT.parent / 'print.html'}")


if __name__ == "__main__":
    main()

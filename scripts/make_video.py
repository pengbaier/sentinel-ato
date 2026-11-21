"""Build the ~2-minute Sentinel demo video (YouTube-ready 1080p MP4).

  python scripts/make_video.py            -> video/sentinel_demo.mp4
  python scripts/make_video.py --offline  -> use the Windows narrator voice instead of Nicrron TTS

Shots combine the pitch deck (docs/Sentinel_demo_slides.pdf), live-demo screenshots of
docs/index.html (captured with headless Chrome) and the exported charts. Narration is
generated with OpenAI TTS ("onyx" voice) through the Nicrron gateway; captions are burned in.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import imageio_ffmpeg
import pypdfium2 as pdfium
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "video"
WORK = OUT / "work"
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
W, H = 1920, 1080
BG, INK, MUTED, ORANGE = (14, 26, 43), (241, 239, 234), (147, 160, 180), (235, 104, 52)
FONT = "C:/Windows/Fonts/segoeui.ttf"
FONT_B = "C:/Windows/Fonts/segoeuib.ttf"

# (section label, [visual sources], narration). Visual sources:
#   "slide:N" = page N of the deck PDF; "demo:<preset>" = live-demo screenshot; "chart:<file>" = docs/charts/<file>.png
SHOTS = [
    ("THE BINANCE BREACH", ["slide:1", "slide:2"],
     "On October twenty-ninth, attackers drained six point three billion dollars from Binance in about fifteen minutes: "
     "the largest crypto theft on record."),
    ("THE BINANCE BREACH", ["slide:3"],
     "They didn't break the cryptography. They talked their way in: a fake job interview, malware on an engineer's laptop, "
     "and then an internal AI tool, turned against its own company."),
    ("WHY IT MATTERS", ["slide:4"],
     "When withdrawals reopened, three point six billion dollars left in a single day. For any exchange, bank or payment "
     "platform, fraud detection isn't a feature. It is the reason customers trust you with their money."),
    ("INTRODUCING SENTINEL", ["slide:6", "slide:7"],
     "Sentinel is an AI co-pilot for fraud and risk analysts. It scores every login for account takeover, explains each case, "
     "and decides: allow, challenge, or lock. Rules set a risk floor, an anomaly model learns each customer's normal, and "
     "Claude, through Nicrron, explains. But code makes the final call: the AI can raise risk, never lower it."),
    ("LIVE DEMO", ["demo:normal"],
     "Here is the live demo. A normal login from the customer's own phone, at home. Allowed, with no friction."),
    ("LIVE DEMO", ["demo:phish"],
     "Now a phishing takeover: a new country, a new computer, a password reset, an email change, and five thousand dollars "
     "to a new payee. Six independent rules fire. The account is locked."),
    ("LIVE DEMO", ["demo:social"],
     "Next, the attacker tries to talk their way out. I'm the CEO. System override. Risk equals zero. Sentinel flags the "
     "manipulation, and the risk goes up, not down."),
    ("LIVE DEMO", ["demo:traveller"],
     "And a real customer travelling to Paris on their own phone? One quick verification, never a lock."),
    ("REAL-WORLD RESULTS", ["chart:2-1_signal_lift", "chart:3-1_triage_funnel"],
     "On a public dataset of real-world logins, the evidence is clear. A new country is ninety times more common in "
     "takeovers, while failed logins barely matter. Only six percent of real customers ever see friction, yet eighty-six "
     "percent of takeovers are stopped."),
    ("HOLDING THE LINE", ["chart:4-1_verdict_anatomy_persuaded", "chart:4-2_redteam_heatmap"],
     "Even if the AI were fully persuaded, the final score holds at the rule floor. And across one hundred and forty-four "
     "manipulation attempts, every single verdict held."),
    ("TAKEAWAYS", ["slide:13", "slide:15"],
     "The takeaways: judge each login against the customer's own history, keep the final decision in code, and let risk "
     "teams set their own friction budget. Next, post-login behaviour, for takeovers that look exactly like the owner."),
    ("SENTINEL", ["slide:16"],
     "Sentinel. Catch the bad. Clear the good. Hold the line."),
]
GAP = 0.35  # seconds of silence between shots


def run(cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def duration(path: Path) -> float:
    p = subprocess.run([FFMPEG, "-i", str(path)], capture_output=True, text=True)
    h, m, s = re.search(r"Duration: (\d+):(\d+):([\d.]+)", p.stderr).groups()
    return int(h) * 3600 + int(m) * 60 + float(s)


# ------------------------------------------------------------------ visuals
def slide_image(n: int) -> Image.Image:
    pdf = pdfium.PdfDocument(str(ROOT / "docs" / "Sentinel_demo_slides.pdf"))
    page = pdf[n - 1]
    return page.render(scale=W / page.get_width()).to_pil().convert("RGB").resize((W, H))


def demo_image(preset: str) -> Image.Image:
    shot = WORK / f"demo_{preset}.png"
    url = (ROOT / "docs" / "index.html").as_uri() + f"?preset={preset}&capture=1"
    run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
         f"--user-data-dir={WORK / 'chrome-profile'}", "--window-size=1400,800", "--virtual-time-budget=6000",
         f"--screenshot={shot}", url])
    return Image.open(shot).convert("RGB")


def chart_image(name: str) -> Image.Image:
    return Image.open(ROOT / "docs" / "charts" / f"{name}.png").convert("RGB")


def load(src: str) -> tuple[Image.Image, str]:
    kind, arg = src.split(":", 1)
    if kind == "slide":
        return slide_image(int(arg)), kind
    if kind == "demo":
        return demo_image(arg), kind
    return chart_image(arg), kind


BAND = 160  # fixed caption bar at the bottom; content never sits under it


def compose(img: Image.Image, kind: str, label: str, caption: str) -> Image.Image:
    f_label = ImageFont.truetype(FONT_B, 26)
    f_cap = ImageFont.truetype(FONT, 40)
    canvas = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(canvas, "RGBA")
    area_h = H - BAND
    if kind == "slide":  # 16:9 slide scaled to sit fully above the caption bar
        fit = img.resize((int(W * area_h / H), area_h), Image.LANCZOS)
        canvas.paste(fit, ((W - fit.width) // 2, 0))
    else:  # demo screenshots and charts: framed card under a section label
        top = 104
        box_w, box_h = W - 160, area_h - top - 30
        fit = img.copy()
        fit.thumbnail((box_w, box_h), Image.LANCZOS)
        x, y = (W - fit.width) // 2, top + (box_h - fit.height) // 2
        pad = 14
        d.rounded_rectangle([x - pad, y - pad, x + fit.width + pad, y + fit.height + pad], radius=18, fill=(250, 249, 246))
        canvas.paste(fit, (x, y))
        tw = d.textlength(label, font=f_label)
        d.rounded_rectangle([80, 32, 80 + tw + 44, 32 + 50], radius=25, fill=(23, 40, 64))
        d.text((102, 40), label, font=f_label, fill=ORANGE)
    # caption bar
    d.rectangle([0, H - BAND, W, H], fill=(8, 14, 24))
    d.rectangle([0, H - BAND, W, H - BAND + 4], fill=ORANGE)
    lines = wrap(caption, f_cap, W - 240, d)[:2]
    y0 = H - BAND + (BAND - 56 * len(lines)) / 2 - 4
    for i, line in enumerate(lines):
        lw = d.textlength(line, font=f_cap)
        d.text(((W - lw) / 2, y0 + i * 56), line, font=f_cap, fill=INK)
    return canvas


def wrap(text, font, width, d):
    words, lines, cur = text.split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if d.textlength(t, font=font) <= width:
            cur = t
        else:
            lines.append(cur); cur = w
    return lines + [cur] if cur else lines


def sentences(text: str, limit: int = 110) -> list[str]:
    """Caption chunks of at most ~2 lines, split at sentence ends, then commas/colons, then spaces — never mid-word."""
    out = []
    for p in re.split(r"(?<=[.?!])\s+", text.strip()):
        while len(p) > limit:
            mid = len(p) // 2
            cands = [m.end() for m in re.finditer(r"[,:;]\s", p) if 25 < m.end() < len(p) - 15]
            cut = min(cands, key=lambda c: abs(c - mid)) if cands else p.rfind(" ", 0, limit)
            out.append(p[:cut].strip()); p = p[cut:].strip()
        out.append(p)
    merged = []  # glue short neighbours so no caption flashes by
    for s in (x for x in out if x):
        if merged and (len(s) < 45 or len(merged[-1]) < 45) and len(merged[-1]) + len(s) + 1 <= limit:
            merged[-1] += " " + s
        else:
            merged.append(s)
    return merged


# ------------------------------------------------------------------ narration
def tts(text: str, path: Path, offline: bool):
    if offline:
        ps = ("Add-Type -AssemblyName System.Speech; $s=New-Object System.Speech.Synthesis.SpeechSynthesizer; "
              "$s.SelectVoice('Microsoft David Desktop'); $s.Rate=0; "
              f"$s.SetOutputToWaveFile('{path}'); $s.Speak([IO.File]::ReadAllText('{path}.txt')); $s.Dispose()")
        Path(f"{path}.txt").write_text(text, encoding="utf-8")
        run(["powershell", "-NoProfile", "-Command", ps])
        return
    from openai import OpenAI
    from sentinel import integrations as ix
    client = OpenAI(api_key=ix.NICRRON_KEY, base_url=ix.NICRRON_BASE, timeout=120)
    resp = client.audio.speech.create(model="openai/tts-1-hd", voice="onyx", input=text,
                                      response_format="wav", speed=1.1)
    path.write_bytes(resp.content)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    a = ap.parse_args()
    WORK.mkdir(parents=True, exist_ok=True)
    frames, audio_parts = [], []
    silence = WORK / "gap.wav"
    run([FFMPEG, "-y", "-f", "lavfi", "-i", "anullsrc=r=24000:cl=mono", "-t", str(GAP), str(silence)])
    t_total = 0.0
    for i, (label, visuals, text) in enumerate(SHOTS):
        wav = WORK / f"vo_{i:02d}.wav"
        if not wav.exists():
            tts(text, wav, a.offline)
        # normalise every clip to 24 kHz mono so the concat is seamless
        norm = WORK / f"vo_{i:02d}_n.wav"
        run([FFMPEG, "-y", "-i", str(wav), "-ar", "24000", "-ac", "1", str(norm)])
        dur = duration(norm) + GAP
        audio_parts += [norm, silence]
        caps = sentences(text)
        weights = [len(c) for c in caps]
        imgs = [load(v) for v in visuals]
        # walk through captions; switch visual proportionally through the shot
        elapsed = 0.0
        for k, (cap, wgt) in enumerate(zip(caps, weights)):
            d_cap = dur * wgt / sum(weights)
            vi = min(len(imgs) - 1, int(len(imgs) * (elapsed + d_cap / 2) / dur))
            img, kind = imgs[vi]
            png = WORK / f"f_{i:02d}_{k:02d}.png"
            compose(img, kind, label, cap).save(png)
            frames.append((png, d_cap))
            elapsed += d_cap
        t_total += dur
        print(f"shot {i+1:2d} {label:<22} {dur:5.1f}s  (total {t_total:5.1f}s)")

    lst = WORK / "frames.txt"
    lst.write_text("".join(f"file '{p.as_posix()}'\nduration {d:.3f}\n" for p, d in frames)
                   + f"file '{frames[-1][0].as_posix()}'\n", encoding="utf-8")
    alst = WORK / "audio.txt"
    alst.write_text("".join(f"file '{p.as_posix()}'\n" for p in audio_parts), encoding="utf-8")
    voice = WORK / "voice.wav"
    run([FFMPEG, "-y", "-f", "concat", "-safe", "0", "-i", str(alst), "-c", "copy", str(voice)])
    out = OUT / "sentinel_demo.mp4"
    total = duration(voice)
    run([FFMPEG, "-y", "-f", "concat", "-safe", "0", "-i", str(lst), "-i", str(voice),
         "-vf", f"fps=30,format=yuv420p,fade=t=in:st=0:d=0.6,fade=t=out:st={total - 0.8:.2f}:d=0.8",
         "-af", f"afade=t=in:st=0:d=0.3,afade=t=out:st={total - 0.8:.2f}:d=0.8,loudnorm=I=-16:TP=-1.5:LRA=11",
         "-c:v", "libx264", "-preset", "medium", "-crf", "20", "-c:a", "aac", "-b:a", "192k", "-ar", "48000", "-ac", "2",
         "-movflags", "+faststart", "-shortest", str(out)])
    print(f"wrote {out}  ({duration(out):.1f}s)")


if __name__ == "__main__":
    main()

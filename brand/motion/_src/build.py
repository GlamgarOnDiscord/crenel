#!/usr/bin/env python3
"""Build the animated Crenel mascot SVGs from brand/icon.svg (drawing untouched)."""
import re
from pathlib import Path

SRC = Path("/root/work/bastion/brand/icon.svg")
OUT = Path("/root/work/bastion/brand/motion")
OUT.mkdir(exist_ok=True)
BASE = SRC.read_text()


def rep(s, old, new):
    assert s.count(old) == 1, (old[:80], s.count(old))
    return s.replace(old, new)


def pct(t, cycle):
    v = t / cycle * 100
    return f"{v:.3f}".rstrip("0").rstrip(".") + "%"


# Blink easing: lids drop fast (ease-in), lift slower (ease-out).
CLOSE_EASE = "cubic-bezier(.55,0,.8,.3)"
OPEN_EASE = "cubic-bezier(.2,.7,.3,1)"


def blink_keyframes(name, cycle, starts, close=0.075, hold=0.03, opn=0.13, closed=0.06):
    """Keyframes of eyes squashed vertically. starts in seconds within cycle."""
    frames = [f"0%{{transform:none;animation-timing-function:{CLOSE_EASE}}}"]
    for s in starts:
        a, b, c, d = s, s + close, s + close + hold, s + close + hold + opn
        frames.append(f"{pct(a, cycle)}{{transform:none;animation-timing-function:{CLOSE_EASE}}}")
        frames.append(f"{pct(b, cycle)},{pct(c, cycle)}{{transform:scaleY({closed});animation-timing-function:{OPEN_EASE}}}")
        frames.append(f"{pct(d, cycle)}{{transform:none;animation-timing-function:{CLOSE_EASE}}}")
    frames.append("100%{transform:none}")
    return f"@keyframes {name}{{{''.join(frames)}}}"


def structure(svg, viewbox=None, size=None):
    """Add hooks (wrapper groups, sheen, glow) without changing any drawn shape."""
    if viewbox:
        svg = rep(svg, 'width="1024" height="1024" viewBox="0 0 1024 1024"',
                  f'width="{size}" height="{size}" viewBox="{viewbox}"')
    svg = rep(svg, "<!-- SVG created with Arrow, by QuiverAI (https://quiver.ai) -->\n", "")
    # Eyes: outer .eye (blink), inner .iris (gaze, clipped to the socket), .glint (extra parallax).
    l_sock = '<ellipse cx="438" cy="437" rx="31" ry="34" fill="#111a2d" opacity=".6"/>'
    r_sock = '<ellipse cx="709" cy="385" rx="28" ry="32" fill="#111a2d" opacity=".7"/>'
    l_eye = re.search(r'    <path id="left-eye" .*?/>\n    <ellipse id="left-eye-reflection" .*?/>\n', svg).group(0)
    r_eye = re.search(r'    <path id="right-eye" .*?/>\n    <ellipse id="right-eye-reflection" .*?/>\n', svg).group(0)

    def eye_block(side, sock, eye, cx, cy, rx, ry):
        lines = eye.strip("\n").split("\n")
        return (f'    <g class="eye eye-{side}">\n      {sock}\n'
                f'      <g class="iris">\n  {lines[0]}\n'
                f'      <g class="glint">\n  {lines[1]}\n      </g></g>\n    </g>\n')

    svg = rep(svg, f"    {l_sock}\n{l_eye}", eye_block("l", l_sock, l_eye, 438, 437, 31, 34))
    svg = rep(svg, f"    {r_sock}\n{r_eye}", eye_block("r", r_sock, r_eye, 709, 385, 28, 32))
    # Socket clips (a hair larger than the sockets so the gold stroke is never cut at rest).
    defs_extra = (
        '    <linearGradient id="sheen" x1="0" y1="0" x2="1" y2="0">\n'
        '      <stop offset="0" stop-color="#fffbe0" stop-opacity="0"/>\n'
        '      <stop offset=".5" stop-color="#fffbe0" stop-opacity=".7"/>\n'
        '      <stop offset="1" stop-color="#fffbe0" stop-opacity="0"/>\n'
        '    </linearGradient>\n'
        '    <filter id="key-glow" x="-30%" y="-40%" width="160%" height="180%"><feGaussianBlur stdDeviation="14"/></filter>\n'
        '  </defs>'
    )
    svg = rep(svg, "  </defs>", defs_extra)
    # Key: glow halo behind it, sheen band clipped to its outline on top of it.
    svg = rep(svg, '  <g id="gold-key">\n',
              '  <use class="halo" href="#key-outline" fill="#ffe14d" filter="url(#key-glow)" opacity="0"/>\n'
              '  <g id="gold-key">\n')
    svg = rep(svg, '  <g id="bird-beak">',
              '  <g clip-path="url(#key-clip)"><g transform="rotate(18 700 640)">'
              '<rect class="sheen" x="330" y="380" width="70" height="520" fill="url(#sheen)" opacity="0"/>'
              '</g></g>\n  <g id="bird-beak">')
    # Stars: inner wrapper so the original translate() on the outer group is kept.
    for sid in ["large-yellow-star", "small-yellow-star", "white-background-star",
                "key-ring-star", "key-shaft-star"]:
        m = re.search(rf'    <g id="{sid}"[^>]*>\n(.*?)\n    </g>\n', svg, re.S)
        inner = m.group(1)
        svg = svg.replace(m.group(0), m.group(0).replace(
            inner, f'      <g class="tw tw-{sid}">\n{inner}\n      </g>'), 1)
    return svg


def inject(svg, css, title):
    style = (f'  <title>{title}</title>\n  <style>\n{css.strip()}\n'
             '@media (prefers-reduced-motion:reduce){*{animation:none!important}}\n  </style>\n')
    return rep(svg, "  <defs>", style + "  <defs>", )


COMMON = """
.eye,.iris,.glint,.tw,.sheen,.halo{transform-box:fill-box;transform-origin:center}
.eye{transform-origin:50% 60%}
"""

SMOOTH = "cubic-bezier(.45,0,.25,1)"

# ---------- idle ----------
IDLE_CYCLE = 15.0
# blinks at 4.1s, 9.3s (double), 13.8s -> gaps 5.2, 4.5, 5.3 (with wrap)
idle_blinks = blink_keyframes("blink", IDLE_CYCLE, [4.1, 9.3, 9.62, 13.8])


def twinkle(name, lo_s=.86, lo_o=.72, rot=0):
    # rest slightly dimmed, swell to full then settle: a breath, not a flash.
    return (f"@keyframes {name}{{"
            f"0%,100%{{transform:scale({lo_s}) rotate(0deg);opacity:{lo_o}}}"
            f"45%{{transform:scale(1.04) rotate({rot}deg);opacity:1}}"
            f"60%{{transform:scale(1) rotate({rot}deg);opacity:1}}}}")


idle_css = COMMON + idle_blinks + "\n" + twinkle("tw", rot=0) + """
@keyframes sheen{0%,82%{transform:translateX(0);opacity:0}83%{opacity:1}97%{transform:translateX(640px);opacity:1}97.1%,100%{transform:translateX(640px);opacity:0}}
.eye{animation:blink 15s infinite}
.tw{animation:tw 4.6s """ + SMOOTH + """ infinite}
.tw-large-yellow-star{animation-duration:5.2s;animation-delay:-1.1s}
.tw-small-yellow-star{animation-duration:4.1s;animation-delay:-3.0s}
.tw-white-background-star{animation-duration:6.3s;animation-delay:-4.4s}
.tw-key-ring-star{animation-duration:4.7s;animation-delay:-.4s}
.tw-key-shaft-star{animation-duration:5.6s;animation-delay:-2.3s}
.sheen{animation:sheen 8.5s cubic-bezier(.4,0,.2,1) infinite;animation-delay:1.2s}
"""

# ---------- working ----------
W = 2.8  # gaze loop
GAZE_X, GLINT_X = 9, 3
work_css = COMMON + f"""
@keyframes gaze{{0%,100%{{transform:translateX(-{GAZE_X}px)}}8%{{transform:translateX(-{GAZE_X}px)}}38%{{transform:translateX(-{GAZE_X}px)}}50%{{transform:translateX({GAZE_X}px)}}88%{{transform:translateX({GAZE_X}px)}}}}
@keyframes glint{{0%,100%{{transform:translateX(-{GLINT_X}px)}}38%{{transform:translateX(-{GLINT_X}px)}}50%{{transform:translateX({GLINT_X}px)}}88%{{transform:translateX({GLINT_X}px)}}}}
@keyframes pulse{{0%,100%{{transform:scale(.84);opacity:.62}}50%{{transform:scale(1.03);opacity:1}}}}
{blink_keyframes("blink", W * 3, [W * 0.92])}
.iris{{animation:gaze {W}s cubic-bezier(.6,0,.25,1) infinite}}
.glint{{animation:glint {W}s cubic-bezier(.6,0,.25,1) infinite}}
.eye{{animation:blink {W*3:.1f}s infinite}}
.tw{{animation:pulse {W}s ease-in-out infinite}}
.tw-key-ring-star{{animation-delay:0s}}
.tw-key-shaft-star{{animation-delay:-.35s}}
.tw-small-yellow-star{{animation-delay:-.7s}}
.tw-large-yellow-star{{animation-delay:-1.05s}}
.tw-white-background-star{{animation-delay:-1.4s}}
"""
# gaze keyframes include 0% and 8% equal (hold); keep as written.

# ---------- found ----------
# 0-0.2s eyes open a touch wider, 0.15-0.85 sheen sweep + halo, stars light up in a
# staggered wave 0.25-1.4s, then the idle loop takes over after 2.4s.
D = 2.4
found_css = COMMON + idle_blinks + "\n" + twinkle("tw", rot=0) + f"""
@keyframes alert{{0%{{transform:none}}10%{{transform:scale(1.07)}}40%{{transform:scale(1.07)}}100%{{transform:none}}}}
@keyframes fsheen{{0%{{transform:translateX(0);opacity:0}}1%{{opacity:1}}99%{{transform:translateX(640px);opacity:1}}100%{{transform:translateX(640px);opacity:0}}}}
@keyframes halo{{0%{{opacity:0}}28%{{opacity:.75}}100%{{opacity:0}}}}
@keyframes light{{0%{{transform:scale(.86);opacity:.72}}30%{{transform:scale(1.32) rotate(12deg);opacity:1}}100%{{transform:scale(.86) rotate(0deg);opacity:.72}}}}
.eye-l,.eye-r{{animation:alert .9s cubic-bezier(.3,0,.2,1) both,blink 15s {D}s infinite}}
.sheen{{animation:fsheen .75s cubic-bezier(.5,0,.25,1) .12s both}}
@keyframes kflash{{0%,100%{{filter:brightness(1)}}30%{{filter:brightness(1.13)}}}}
#gold-key{{animation:kflash 1.2s cubic-bezier(.25,0,.2,1) .1s both}}
.halo{{animation:halo 1.5s cubic-bezier(.2,0,.2,1) .1s both}}
.tw{{animation:light 1.1s cubic-bezier(.25,0,.2,1) both,tw 4.6s {SMOOTH} {D}s infinite}}
.tw-key-ring-star{{animation-delay:.18s,{D}s;animation-duration:1.1s,4.7s}}
.tw-key-shaft-star{{animation-delay:.3s,{D+.9}s;animation-duration:1.1s,5.6s}}
.tw-small-yellow-star{{animation-delay:.42s,{D+.4}s;animation-duration:1.1s,4.1s}}
.tw-large-yellow-star{{animation-delay:.52s,{D+1.6}s;animation-duration:1.1s,5.2s}}
.tw-white-background-star{{animation-delay:.62s,{D+.6}s;animation-duration:1.1s,6.3s}}
"""

# ---------- loader (24-40px) ----------
L = 2.4
loader_css = COMMON + f"""
@keyframes ltw{{0%,100%{{transform:scale(.5);opacity:.4}}40%{{transform:scale(1.3);opacity:1}}62%{{transform:scale(1.05);opacity:1}}}}
@keyframes lsheen{{0%,40%{{transform:translateX(0) scaleX(1.8);opacity:0}}41%{{opacity:1}}80%{{transform:translateX(640px) scaleX(1.8);opacity:1}}80.1%,100%{{transform:translateX(640px) scaleX(1.8);opacity:0}}}}
@keyframes lkey{{0%,30%,100%{{filter:brightness(1)}}60%{{filter:brightness(1.12)}}}}
#gold-key{{animation:lkey {L}s ease-in-out infinite}}
{blink_keyframes("blink", L * 2, [L * 1.55], close=.09, hold=.07, opn=.16, closed=.05)}
.eye{{animation:blink {L*2:.1f}s infinite}}
.tw{{animation:ltw {L}s {SMOOTH} infinite}}
.tw-key-ring-star{{animation-delay:0s}}
.tw-key-shaft-star{{animation-delay:-{L*2/3:.2f}s}}
.tw-small-yellow-star{{animation-delay:-{L/3:.2f}s}}
.tw-large-yellow-star{{animation-delay:-{L*0.5:.2f}s}}
.sheen{{animation:lsheen {L}s cubic-bezier(.45,0,.25,1) infinite}}
"""

files = {
    "crenel-idle.svg": (structure(BASE), idle_css, "Crenel"),
    "crenel-working.svg": (structure(BASE), work_css, "Crenel is working"),
    "crenel-found.svg": (structure(BASE), found_css, "Crenel found an issue"),
    "crenel-loader.svg": (structure(BASE, "250 130 720 720", 40), loader_css, "Loading"),
}
for name, (svg, css, title) in files.items():
    out = inject(svg, css, title)
    (OUT / name).write_text(out)
    print(name, len(out))
